/* MIT License
 *
 * Copyright (c) 2024 The c-ares project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ares_private.h"
#include "ares_strset.h"

/* The linked-list value, not the string itself: it ties the ordered list and
 * the membership hash table to the same owned copy of the string. */
typedef struct {
  char *str; /*!< owned copy, also referenced by the hash table */
} ares_strset_entry_t;

struct ares_strset {
  /*! insertion-ordered strings; owns the ares_strset_entry_t records */
  ares_llist_t        *list;
  /*! case-insensitive membership index; the key is the duplicated string, the
   *  value is the matching list node so removal could be implemented later.
   *  The list remains the owner of the entry record and string. */
  ares_htable_strvp_t *hash;
};

static void ares_strset_entry_destroy(void *arg)
{
  ares_strset_entry_t *entry = arg;

  if (entry == NULL) {
    return;
  }
  ares_free(entry->str);
  ares_free(entry);
}

ares_strset_t *ares_strset_create(void)
{
  ares_strset_t *set = ares_malloc_zero(sizeof(*set));

  if (set == NULL) {
    return NULL; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  set->list = ares_llist_create(ares_strset_entry_destroy);
  if (set->list == NULL) {
    ares_strset_destroy(set);
    return NULL; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* Values are non-owning back-pointers into the list; the list owns them. */
  set->hash = ares_htable_strvp_create(NULL);
  if (set->hash == NULL) {
    ares_strset_destroy(set);
    return NULL; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  return set;
}

void ares_strset_destroy(ares_strset_t *set)
{
  if (set == NULL) {
    return;
  }

  ares_htable_strvp_destroy(set->hash);
  ares_llist_destroy(set->list);
  ares_free(set);
}

const char *ares_strset_insert_get(ares_strset_t *set, const char *str)
{
  ares_strset_entry_t *entry;
  ares_llist_node_t   *node;
  const char          *existing;

  if (set == NULL || str == NULL) {
    return NULL; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  existing = ares_htable_strvp_get_direct(set->hash, str);
  if (existing != NULL) {
    return existing;
  }

  entry = ares_malloc_zero(sizeof(*entry));
  if (entry == NULL) {
    return NULL; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  entry->str = ares_strdup(str);
  if (entry->str == NULL) {
    ares_free(entry); /* LCOV_EXCL_LINE: OutOfMemory */
    return NULL;      /* LCOV_EXCL_LINE: OutOfMemory */
  }

  node = ares_llist_insert_last(set->list, entry);
  if (node == NULL) {
    ares_strset_entry_destroy(entry); /* LCOV_EXCL_LINE: OutOfMemory */
    return NULL;                      /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* The hash table stores the string copy the list owns.  On failure the
   * inserted list node is rolled back so the set stays consistent. */
  if (!ares_htable_strvp_insert(set->hash, entry->str, (char *)entry->str)) {
    ares_llist_node_destroy(node); /* LCOV_EXCL_LINE: OutOfMemory */
    return NULL;                   /* LCOV_EXCL_LINE: OutOfMemory */
  }

  return entry->str;
}

ares_bool_t ares_strset_insert(ares_strset_t *set, const char *str)
{
  return ares_strset_insert_get(set, str) != NULL;
}

ares_bool_t ares_strset_contains(const ares_strset_t *set, const char *str)
{
  if (set == NULL || str == NULL) {
    return ARES_FALSE;
  }

  if (ares_htable_strvp_get_direct(set->hash, str) != NULL) {
    return ARES_TRUE;
  }

  return ARES_FALSE;
}

size_t ares_strset_len(const ares_strset_t *set)
{
  if (set == NULL) {
    return 0;
  }
  return ares_llist_len(set->list);
}

const char *ares_strset_first(const ares_strset_t *set)
{
  return ares_strset_node_val(ares_strset_node_first(set));
}

ares_strset_node_t *ares_strset_node_first(const ares_strset_t *set)
{
  if (set == NULL) {
    return NULL;
  }
  return ares_llist_node_first(set->list);
}

ares_strset_node_t *ares_strset_node_next(ares_strset_node_t *node)
{
  return ares_llist_node_next(node);
}

const char *ares_strset_node_val(ares_strset_node_t *node)
{
  ares_strset_entry_t *entry;

  if (node == NULL) {
    return NULL;
  }

  entry = ares_llist_node_val(node);
  if (entry == NULL) {
    return NULL; /* LCOV_EXCL_LINE: DefensiveCoding */
  }
  return entry->str;
}
