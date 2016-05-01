/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

/*
 * This list implementation is originally based on the
 * double-linked list implementaton from the linux-kernel
 * which can be found in include/linux/list.h
 *
 * The following has been changed/added to better fit my needs:
 * - items counter
 * - plist handler (list-node structure with void* item pointer
 * - single-linked list instead of double-linked list to save overhead
 * - some functions for straight item access!
 * - ...
 */
#include <string.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "tools.h"
#include "allocate.h"

/**
 * list_iterate - return pointer to next node maintained in the list or NULL
 * @head: list head of maintained nodes
 * @node: a node maintained in the list or NULL
 */
void * list_iterate(struct list_head *head, void *node)
{
        struct list_node *ln = (node ?
                ((struct list_node*) (((char*) node) + head->list_node_offset)) :
                ((struct list_node*) head));

        assertion(-501044, (IMPLIES((!node && head->last == ln), !head->items)));

        if (ln->next == ((struct list_node*) head))
                return NULL;

        return (((char*) ln->next) - head->list_node_offset);
}

void *list_find_next(struct list_head *head, void* key, void *node)
{
        while ((node = list_iterate(head, node))) {

                if (memcmp(((char*)node) + head->key_node_offset, key, head->key_length) == 0)
                        return node;
        }
        return NULL;
}

/**
 * list_add_head - add a new entry at the beginning of a list
 * @head: list head to add it after
 * @new: new entry to be added
 */
void list_add_head(struct list_head *head, struct list_node *new)
{

        new->next = head->next;
        head->next = new;

        if (head->last == (struct list_node *) head)
                head->last = new;

        head->items++;

}


/**
 * list_add_tail - add a new entry
 * @head: list head to add it before
 * @new: new entry to be added
 */

void list_add_tail(struct list_head *head, struct list_node *new )
{
        new->next = (struct list_node *) head;
        head->last->next = new;

        head->last = new;
        head->items++;
}


void list_add_after(struct list_head *head, struct list_node *ln, struct list_node *new)
{
        new->next = ln->next;
        ln->next = new;

        if (head->last == ln)
                head->last = new;

        head->items++;
}





/**
 * list_del_next - deletes next entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty on entry does not return true after this, the entry is in an undefined state.
 */
void list_del_next(struct list_head *head, struct list_node *ln)
{
        assertion(-502641, (ln->next != (struct list_node*) head));

        struct list_node *rem = ln->next;

        if (head->last == rem)
                head->last = ln;

        ln->next = rem->next;

        head->items--;
}

void *list_del_head(struct list_head *head)
{
        if (LIST_EMPTY(head))
                return NULL;

        struct list_node* entry = head->next;

        list_del_next(head, (struct list_node*) head);

        return (((char*) entry) - head->list_node_offset);
}



/**
 * plist_get_next - return pointer to next node maintained in the list or NULL
 * @head: list head of maintained nodes
 * @@pnode: MBZ at beginning!  pointing to current plist_node in list
 */
/* UNTESTED
void * plist_iterate(struct list_head *head, struct plist_node **pln)
{

        if (head->last == (struct list_node*)
                (*pln = *pln ? (struct plist_node*) ((*pln)->list.next) : (struct plist_node*) (head->next)))
                return NULL;

        return (*pln)->item;

}
*/


static struct plist_node *plist_node_create(void *item)
{
        assertion(-500266, (item));
        struct plist_node *plh = debugMalloc(sizeof ( struct plist_node), -300113);

        plh->item = item;
        return plh;
}

void plist_add_head(struct list_head *head, void *item)
{
        list_add_head(head, &((plist_node_create(item))->list));
}

void plist_add_tail(struct list_head *head, void *item)
{
        list_add_tail(head, &((plist_node_create(item))->list));
}

void * plist_del_head(struct list_head *head)
{
        struct plist_node *pln = list_del_head(head);

        if ( !pln )
                return NULL;

        void *item = pln->item;
        
        debugFree( pln, -300114 );

        return item;
}
