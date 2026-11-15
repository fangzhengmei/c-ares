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
#ifndef __ARES__STRSET_H
#define __ARES__STRSET_H

#include "ares_llist.h"

/*! \addtogroup ares_strset Ordered, de-duplicating string set
 *
 * A set of strings that preserves first-insertion order and de-duplicates
 * case-insensitively, the way hostname comparison works elsewhere in the
 * library.  It is backed by a linked list for ordered iteration and a hash
 * table for membership, so insertion, lookup and de-duplication are all O(1)
 * while still allowing deterministic, file-ordered iteration.
 *
 * This exists so callers that would otherwise append strings to a list and
 * linearly scan it for duplicates (which is O(n^2) on the pathological inputs
 * a hosts file may contain) get deduplication and ordered iteration from one
 * helper instead of hand-rolling either.  Stored strings are copies owned by
 * the set; the caller's buffer is never referenced afterwards.
 *
 * @{
 */

struct ares_strset;

/*! Opaque data type for the ordered string set implementation */
typedef struct ares_strset ares_strset_t;

/*! Node in the insertion order of a set.  This is an ares_llist node so the
 *  usual ares_llist_node_*() traversal helpers may also be used, but the node
 *  value must be obtained with ares_strset_node_val() (the raw list value is
 *  an internal bookkeeping structure, not the string). */
typedef ares_llist_node_t  ares_strset_node_t;

/*! Create an empty set.
 *
 *  \return initialized set, or NULL on out of memory
 */
CARES_EXTERN ares_strset_t *ares_strset_create(void);

/*! Destroy a set and every string it owns.
 *
 *  \param[in] set  Initialized set, may be NULL
 */
CARES_EXTERN void ares_strset_destroy(ares_strset_t *set);

/*! Insert a string, keeping first-insertion order and de-duplicating
 *  case-insensitively.  Inserting a string that is already present is not an
 *  error and does not change the order.
 *
 *  \param[in] set  Initialized set
 *  \param[in] str  Non-NULL string to insert (a copy is stored)
 *  \return ARES_TRUE on success (including when already present),
 *          ARES_FALSE on out of memory or misuse
 */
CARES_EXTERN ares_bool_t ares_strset_insert(ares_strset_t *set,
                                            const char    *str);

/*! Insert a string and return the copy stored by the set.  When an equal
 *  string is already present its stored copy is returned and no insertion
 *  occurs, so the caller can always hold on to the returned pointer as long as
 *  the set exists.  This is the variant to use when the caller needs a stable
 *  reference to the string (e.g. to record it elsewhere) without duplicating
 *  it a second time.
 *
 *  \param[in] set  Initialized set
 *  \param[in] str  Non-NULL string to insert (a copy is stored if new)
 *  \return stored string owned by the set, or NULL on out of memory or misuse
 */
CARES_EXTERN const char *ares_strset_insert_get(ares_strset_t *set,
                                                const char    *str);

/*! Test case-insensitive membership.
 *
 *  \param[in] set  Initialized set, may be NULL
 *  \param[in] str  String to look for, may be NULL
 *  \return ARES_TRUE if present, otherwise ARES_FALSE
 */
CARES_EXTERN ares_bool_t ares_strset_contains(const ares_strset_t *set,
                                              const char          *str);

/*! Number of strings in the set.
 *
 *  \param[in] set  Initialized set, may be NULL
 *  \return number of strings, 0 when set is NULL
 */
CARES_EXTERN size_t ares_strset_len(const ares_strset_t *set);

/*! First string in insertion order.
 *
 *  \param[in] set  Initialized set, may be NULL
 *  \return first string, or NULL if the set is empty or NULL
 */
CARES_EXTERN const char *ares_strset_first(const ares_strset_t *set);

/*! First node in insertion order, for ordered traversal.
 *
 *  \param[in] set  Initialized set, may be NULL
 *  \return first node, or NULL if the set is empty or NULL
 */
CARES_EXTERN ares_strset_node_t *
  ares_strset_node_first(const ares_strset_t *set);

/*! Node following the given node in insertion order.
 *
 *  \param[in] node  node from ares_strset_node_first()/next(), may be NULL
 *  \return next node, or NULL at the end of the set
 */
CARES_EXTERN ares_strset_node_t *
  ares_strset_node_next(ares_strset_node_t *node);

/*! String held by a node returned from ares_strset_node_first()/next().
 *
 *  \param[in] node  node from ares_strset_node_first()/next(), may be NULL
 *  \return string owned by the set, or NULL if node is NULL
 */
CARES_EXTERN const char *ares_strset_node_val(ares_strset_node_t *node);

/*! @} */

#endif /* __ARES__STRSET_H */
