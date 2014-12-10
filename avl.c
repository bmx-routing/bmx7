/*
 * Copyright (c) 2010  Axel Neumann
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
 * avl code inspired by templates from Julienne Walker at
 * http://eternallyconfuzzled.com/tuts/datastructures/jsw_tut_avl.aspx
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "avl.h"
#include "allocate.h"

#define CODE_CATEGORY_NAME "avl"

struct avl_node *avl_find( struct avl_tree *tree, void *key )
{
        struct avl_node *an = tree->root;
        int cmp;

        // Search for a dead path or a matching entry
        while ( an  &&  ( cmp = memcmp( AVL_NODE_KEY( tree, an ), key, tree->key_size) ) )
                an = an->down[ cmp < 0 ];

        return an;
}

void *avl_find_item(struct avl_tree *tree, void *key)
{
        struct avl_node *an;

        return ((an = avl_find(tree, key)) ? an->item : NULL);

}

STATIC_FUNC
struct avl_node *avl_first(struct avl_tree *tree)
{
#ifdef AVL_5XLINKED
	return tree->first;
#else
        struct avl_node * an = tree->root;

        while (an && an->down[0])
                an = an->down[0];

        return an;
#endif
}

STATIC_FUNC
struct avl_node *avl_next(struct avl_tree *tree, void *key)
{
        if(!key)
                return avl_first(tree);

        struct avl_node *an = tree->root;
        struct avl_node *best = NULL;
        int cmp;

        while (an) {

                cmp = (memcmp(AVL_NODE_KEY(tree, an), key, tree->key_size) <= 0);

                if (an->down[cmp]) {
                        best = cmp ? best : an;
                        an = an->down[cmp];
                } else {
                        return cmp ? best : an;
                }

        }
        return NULL;
}

void * avl_next_item( struct avl_tree *tree, void *key)
{
        struct avl_node *an = avl_next(tree, key);

        return an ? an->item : NULL;
}


void * avl_closest_item(struct avl_tree *tree, void *key) {
	
	void *item = avl_find_item(tree, key);

	return item ? item : avl_next_item(tree, key);
}


void *avl_first_item(struct avl_tree *tree)
{
#ifdef AVL_5XLINKED
	return tree->first ? tree->first->item : NULL;
#else
        struct avl_node * an = avl_first(tree);

        return an ? an->item : NULL;
#endif
}

/*
struct avl_node *avl_iterate(struct avl_tree *tree, struct avl_node *an )
{

        if ( !an || an->link[1] ) {

                an = an ? an->link[1] : tree->root;

                while ( an && an->link[0] )
                        an = an->link[0];

                return an;
        }

        struct avl_node *prev = an;

        while ((an = an->up)) {

                if ( an->link[0] == prev )
                        return an;

                prev = an;
        }

        return NULL;
}
*/


void *avl_iterate_item(struct avl_tree *tree, struct avl_node **an )
{
#ifdef AVL_5XLINKED
	(*an) = (*an) ? (*an)->right : tree->first;

	return (*an) ? (*an)->item : NULL;
#else
        if ( !(*an) || (*an)->down[1] ) {

                (*an) = (*an) ? (*an)->down[1] : tree->root;

                while ( (*an) && (*an)->down[0] )
                        (*an) = (*an)->down[0];

                return (*an) ? (*an)->item : NULL;
        }

        struct avl_node *prev = (*an);

        while (((*an) = (*an)->up)) {

                if ( (*an)->down[0] == prev)
                        return (*an)->item;

                prev = (*an);
        }

        return NULL;
#endif
}

void *_avl_find_item_by_field(struct avl_tree *tree, void *value, unsigned long offset, uint32_t size)
{
        struct avl_node *an = NULL;
        void *item = NULL;

        while ((item = avl_iterate_item(tree, &an))) {
                if (!memcmp(value, (((char*)(an->item)) + offset), size))
                        break;
        }

        return item;
}


STATIC_FUNC
struct avl_node *avl_create_node(struct avl_tree *tree, void *node, int32_t tag, struct avl_node *up, struct avl_node *left, struct avl_node *right)
{
        struct avl_node *an = debugMallocReset(sizeof (struct avl_node), tag);

        an->item = node;
	an->up = up;
#ifdef AVL_5XLINKED
	an->left = left;
	an->right = right;

	if (left) {
		assertion(-502001, (left->right==right));
		left->right = an;
	} else {
		tree->first = an;
	}

	if (right) {
		assertion(-502002, (right->left==left));
		right->left = an;
	} else {
		tree->last = an;
	}
#endif
	tree->items++;
	
	return an;
}

STATIC_FUNC
struct avl_node *avl_rotate_single(struct avl_node *root, int dir)
{
	struct avl_node *save;
	int rlh, rrh, slh;

	/* Rotate */
        save = root->down[!dir];

        root->down[!dir] = save->down[dir];

        if (root->down[!dir])
                root->down[!dir]->up = root;

	save->down[dir] = root;

        if ( root )
                root->up = save;

	/* Update balance factors */
	rlh = avl_height(root->down[0]);
	rrh = avl_height(root->down[1]);
	slh = avl_height(save->down[!dir]);

	root->balance = avl_max(rlh, rrh) + 1;
	save->balance = avl_max(slh, root->balance) + 1;

	return save;
}

STATIC_FUNC
struct avl_node *avl_rotate_double(struct avl_node *root, int dir)
{
	root->down[!dir] = avl_rotate_single(root->down[!dir], !dir);

        if (root->down[!dir])
                root->down[!dir]->up = root;

	return avl_rotate_single(root, dir);
}

void avl_insert(struct avl_tree *tree, void *node, int32_t tag)
{

	struct avl_node *new = NULL;

        if (tree->root) {

                struct avl_node *it = tree->root;
                struct avl_node *up[AVL_MAX_HEIGHT];
                int upd[AVL_MAX_HEIGHT];
		int top = 0;
		int ngi; // node greater it
                int done = 0;
#ifdef AVL_5XLINKED
		struct avl_node *left = NULL; // it less-equal node
		struct avl_node *right = NULL; // it greater node
#endif

                // Search for an empty link, save the path
                for (;;) {
                        // Push direction and node onto stack */
			ngi = (memcmp(AVL_NODE_KEY(tree, it), AVL_ITEM_KEY(tree, node), tree->key_size) <= 0);
#ifdef AVL_5XLINKED
			if (ngi)
				left = it;
			else
				right = it;
#endif
                        upd[top] = ngi;
                        up[top] = it;
                        top++;

                        if (it->down[ngi] == NULL)
                                break;

                        it = it->down[ngi];
                }

                // Insert a new node at the bottom of the tree:
#ifdef AVL_5XLINKED
                new = (it->down[ngi] = avl_create_node(tree, node, tag, it, left, right));
#else
		new = (it->down[ngi] = avl_create_node(tree, node, tag, it, NULL, NULL));
#endif
                assertion(-500178, (it->down[upd[top - 1]]));

                // Walk back up the search path
                while (--top >= 0 && !done) {

                        int lh, rh, max;

                        lh = avl_height(up[top]->down[upd[top]]);
                        rh = avl_height(up[top]->down[!upd[top]]);

                        // Terminate or rebalance as necessary:
                        if (lh - rh == 0)
                                done = 1;
                        if (lh - rh >= 2) {
                                struct avl_node *a = up[top]->down[upd[top]]->down[upd[top]];
                                struct avl_node *b = up[top]->down[upd[top]]->down[!upd[top]];

                                if (avl_height(a) >= avl_height(b))
                                        up[top] = avl_rotate_single(up[top], !upd[top]);
                                else
                                        up[top] = avl_rotate_double(up[top], !upd[top]);

                                // Fix parent:
                                if (top != 0) {
                                        up[top - 1]->down[upd[top - 1]] = up[top];
                                        up[top]->up = up[top - 1];
                                } else {
                                        tree->root = up[0];
                                        up[0]->up = NULL;

                                }

                                done = 1;
                        }

                        // Update balance factors:
                        lh = avl_height(up[top]->down[upd[top]]);
                        rh = avl_height(up[top]->down[!upd[top]]);
                        max = avl_max(lh, rh);

                        up[top]->balance = max + 1;
                }

        } else {

                new = (tree->root = avl_create_node(tree, node, tag, NULL, NULL, NULL));
        }

	assertion(-502003, (new));
#ifdef AVL_5XLINKED
	assertion(-502004, ( new->left  || avl_first(tree)==new));
	assertion(-502005, (!new->left  || avl_next(tree, AVL_ITEM_KEY(tree, new->left->item))==new));
	assertion(-502006, (!new->right || avl_next(tree, AVL_ITEM_KEY(tree, new->item))==new->right));
#endif
        return;
}



void *avl_remove(struct avl_tree *tree, void *key, int32_t tag)
{
	assertion_dbg(-501570, (key), "key=NULL, tag=%d", tag);
	assertion(-501571, (tag <=-300000 && tag > -400000));

        struct avl_node *it = tree->root;
        struct avl_node *up[AVL_MAX_HEIGHT];
        int upd[AVL_MAX_HEIGHT], top = 0, cmp;

        if (!it)
                return NULL;

        while (1) {

                dbgf_all(DBGT_INFO, "tree.items=%d it->item=%p memcmp(it,key)=%d link[0]=%p link[1]=%p memcmp(link[0],key)=%d memcmp(link[1],key)=%d",
                        tree->items, it->item,
                        memcmp(AVL_NODE_KEY(tree, it), key, tree->key_size),
                        (void*) (it->down[0]), (void*) (it->down[1]),
                        (it->down[0] ? memcmp(AVL_NODE_KEY(tree, it->down[0]), key, tree->key_size) : -1),
                        (it->down[1] ? memcmp(AVL_NODE_KEY(tree, it->down[1]), key, tree->key_size) : -1)
                        );

                if (!(
                        (cmp = memcmp(AVL_NODE_KEY(tree, it), key, tree->key_size)) ||
                        (it->down[0] && !memcmp(AVL_NODE_KEY(tree, it->down[0]), key, tree->key_size))))
                        break;

                // Push direction and node onto stack
                upd[top] = (cmp < 0);
                up[top] = it;
                top++;

                if (!(it = it->down[(cmp < 0)]))
                        return NULL;

        }

        // remember and return the found node. It might have been another one than intended
        void *node = it->item;

#ifdef AVL_5XLINKED
	// fix left,right,first,last:
	struct avl_node *left = it->left;
	struct avl_node *right = it->right;

	if (tree->first == it)
		tree->first = right;

	if (tree->last == it)
		tree->last = left;

	if (left)
		left->right = right;

	if (right)
		right->left = left;
#endif

        // Remove the node:
        if (!(it->down[0] && it->down[1])) { // at least one child is NULL:

                // Which child is not null?
                int dir = !(it->down[0]);

                /* Fix parent */
                if (top) {
                        up[top - 1]->down[upd[top - 1]] = it->down[dir];
                        if (it->down[dir])
                                it->down[dir]->up = up[top - 1];
                } else {
                        tree->root = it->down[dir];
                        if (tree->root)
                                tree->root->up = NULL;
                }

                debugFree(it, tag);

        } else { // both childs NOT NULL:

                // Find the inorder successor
                struct avl_node *heir = it->down[1];

                // Save the path
                upd[top] = 1;
                up[top] = it;
                top++;

                while (heir->down[0]) {
                        upd[top] = 0;
                        up[top] = heir;
                        top++;
                        heir = heir->down[0];
                }

                // Swap data
                it->item = heir->item;

                // Unlink successor and fix parent
                up[top - 1]->down[ (up[top - 1] == it) ] = heir->down[1];

                if ( heir->down[1])
                        heir->down[1]->up = up[top - 1];

#ifdef AVL_5XLINKED
		// fix left/right caches:
		if (left==heir)
			left=it;
		if (right==heir)
			right=it;

		// fix left,right,first,last:

		if (tree->first == heir)
			tree->first = it;

		if (tree->last == heir)
			tree->last = it;

		it->left = heir->left;

		if (heir->left)
			heir->left->right = it;

		it->right = heir->right;

		if (heir->right)
			heir->right->left = it;
#endif
                debugFree(heir, tag);

        }

        tree->items--;

        // Walk back up the search path
        while (--top >= 0) {
                int lh = avl_height(up[top]->down[upd[top]]);
                int rh = avl_height(up[top]->down[!upd[top]]);
                int max = avl_max(lh, rh);

                /* Update balance factors */
                up[top]->balance = max + 1;


                // Terminate or re-balance as necessary:
                if (lh - rh >= 0)  // re-balance upper path...
                        continue;

                if (lh - rh == -1) // balance for upper path unchanged!
                        break;

                if (!(up[top]) || !(up[top]->down[!upd[top]])) {
                        dbgf_sys(DBGT_ERR, "up(top) %p  link %p   lh %d   rh %d",
                                (void*)(up[top]), (void*)((up[top]) ? (up[top]->down[!upd[top]]) : NULL), lh, rh);

                        assertion(-500187, (up[top]));
                        assertion(-500188, (up[top]->down[!upd[top]]));
                }

                // if (lh - rh <= -2):  rebalance here and upper path

                struct avl_node *a = up[top]->down[!upd[top]]->down[upd[top]];
                struct avl_node *b = up[top]->down[!upd[top]]->down[!upd[top]];

                if (avl_height(a) <= avl_height(b))
                        up[top] = avl_rotate_single(up[top], upd[top]);
                else
                        up[top] = avl_rotate_double(up[top], upd[top]);

                // Fix parent:
                if (top) {
                        up[top - 1]->down[upd[top - 1]] = up[top];
                        up[top]->up = up[top - 1];
                } else {
                        tree->root = up[0];
                        tree->root->up = NULL;
                }
        }

#ifdef AVL_5XLINKED
	assertion(-502007, (!left  ||   left->left   || avl_first(tree)==left));
	assertion(-502008, (!left  ||  !left->left   || avl_next(tree, AVL_ITEM_KEY(tree, left->left->item))==left));
	assertion(-502009, (!left  ||  !left->right  || avl_next(tree, AVL_ITEM_KEY(tree, left->item))==left->right));

	assertion(-502010, (!right ||  right->left   || avl_first(tree)==right));
	assertion(-502011, (!right || !right->left   || avl_next(tree, AVL_ITEM_KEY(tree, right->left->item))==right));
	assertion(-502012, (!right || !right->right  || avl_next(tree, AVL_ITEM_KEY(tree, right->item))==right->right));
#endif
        return node;

}


void *avl_remove_first_item(struct avl_tree *tree, int32_t tag) {

        void *oitem = NULL;
	void *ritem = NULL;
        struct avl_node *an = avl_first(tree);

        if (an) {
		oitem = an->item;
                ritem = avl_remove(tree, ((uint8_t*)an->item) + tree->key_offset, tag);
                assertion(-501400, (oitem == ritem));
        }

        return ritem;
}

#ifdef AVL_DEBUG

struct avl_node *_avl_iter_down(int dir, struct avl_node *an, struct avl_iterator *it ) {

        for (; an; it->top++) {
                /* Push direction and node onto stack */
                it->up[it->top] = an;
                it->upd[it->top] = dir;

                an = an->link[dir];
        }
        it->top--;
        return it->up[it->top];
}

struct avl_node *avl_iter(struct avl_tree *tree, struct avl_iterator *it ) {

        struct avl_node *an = tree->root;
        if ( !an )
                return NULL;

        if (!it->up[0]) {
                // Get initial element and fill stack:
                // go left...
                it->top=0;
                return _avl_iter_down( 0/*left*/, an, it );
        }

        if ((an = it->up[(it->top)]->link[1])) {
                //go one right, then left...
                it->upd[it->top] = 1;
                it->top++;
                return _avl_iter_down(0, an, it);
        }

        while (it->top > 0 && it->upd[(it->top) - 1] == 1 /*was: down right*/) {
                //so go one back up (up-left = opposite of down right)
                it->top--;
        }

        if (it->top > 0 && it->upd[(it->top) - 1] == 0 /*was: down left*/) {
                //so go one back up (up-right = opposite of down left)):
                it->top--;
                return it->up[it->top];
        }

        it->up[0] = NULL;
        return NULL;
}

void avl_debug( struct avl_tree *tree ) {

        #define AVL_DBG_COL_CHARS 6

        int i,j;

        int depth_min = 0;

        struct avl_node *an;
        for (an = tree->root; an; an = an->link[0])
                depth_min++;

        int depth_max = depth_min+2;
        int width = 1<<depth_max;

        char * dbg_mem = malloc( depth_max * width * AVL_DBG_COL_CHARS + 1);
        memset( dbg_mem, ' ', depth_max * width * AVL_DBG_COL_CHARS + 1 );

        for( i=1; i<=depth_max; i++ )
                dbg_mem[(i*width*AVL_DBG_COL_CHARS)-1] = '\n';

        dbg_mem[ depth_max * width * AVL_DBG_COL_CHARS ] = 0;

        struct avl_iterator it;
        memset ( &it, 0, sizeof( struct avl_iterator ) );

        while( (an = avl_iter( tree, &it )) ) {

                j = (width - 1) * AVL_DBG_COL_CHARS / 2;

                for (i = 0; i < it.top; i++) {

                        int k = ((width - 1) * AVL_DBG_COL_CHARS );
                        int l = 4<<i;
                        int m = ( it.upd[i]?1:-1);

                        j = j + (m * k / l);
                }

//                dbg_mem[((i * width * AVL_DBG_COL_CHARS) + j)] = 'x';

                snprintf(&dbg_mem[((i * width * AVL_DBG_COL_CHARS) + j)], AVL_DBG_COL_CHARS,
                        "%3d/%1d", ((int*) AVL_NODE_KEY(tree, an))[0], ((int*) AVL_NODE_KEY(tree, an))[1]);

                dbg_mem[((i * width * AVL_DBG_COL_CHARS) + j + (AVL_DBG_COL_CHARS-1))] = ' ';


                printf("%3d/%1d ", ((int*) AVL_NODE_KEY(tree, an))[0], ((int*) AVL_NODE_KEY(tree, an))[1]);
        }


        dbg_mem[ depth_max * width * AVL_DBG_COL_CHARS ] = 0;

        printf("\n-----\n%s\n-----\n", dbg_mem );

}
#endif

#ifdef AVL_TEST

void avl_test( int max ) {

#define AVL_TEST_MAX max

        struct test_type {
                int32_t test_key;
                int32_t v;
                uint8_t k;
                int32_t test_key2;
                int32_t w;
        };

        struct avl_node *an = NULL;
        AVL_TREE(test_tree, struct test_type, test_key );
        AVL_TREE(test_tree2, struct test_type, test_key2 );

        int32_t i, j;

        struct test_type * t;

        
        
        // insert something:

        for (i = 0; i <= AVL_TEST_MAX; i++) {
                t = debugMalloc(sizeof ( struct test_type), -300004);
                t->test_key = i;
                t->test_key2 = AVL_TEST_MAX-i;
                t->v = t->w = 0;
                avl_insert(&test_tree, t, -300300);
                avl_insert(&test_tree2, t, -300301);
                printf(" inserted %d/%d %d/%d\n", t->test_key, t->v, t->test_key2, t->w );
        }

/*
        // remove something:

        for (i = AVL_TEST_MAX/2; i >= 0; i--) {

                t = avl_remove(&test_tree, &i, -300302);

                if ( t != avl_remove(&test_tree2, &t->test_key2, -300303) )
                        printf("ERROR...\n");

                printf(" removed %d/%d %d/%d\n", t->test_key, t->v, t->test_key2, t->w );
                debugFree( t, -300038 );
        }
*/




        // debug test_tree:

        printf("\navl_iterate( test_tree ):\n");
        i=0;
        an = NULL;
        while( (an = avl_iterate( &test_tree, an ) ) ) {
                t = ((struct test_type*)(an->item));
                if ( i > t->test_key)
                        printf("\nERROR %d > %d \n", i, t->test_key);
                i = t->test_key;
                printf( "%3d/%1d ", t->test_key, t->v );
        }

        printf("\navl_next():\n");
        i = 0; j = 0;
        while( (an = avl_next( &test_tree,  &j )) ) {
                t = ((struct test_type*)(an->item));
                j = t->test_key;
                if ( i > t->test_key)
                        printf("\nERROR %d > %d \n", i, t->test_key);

                i = t->test_key;

                printf( "N%4d/%1d ", t->test_key, t->v );

                if ( i%10 == 0 )
                        printf("\n");

        }

#ifdef AVL_DEBUG
        printf("\navl_debug():\n");
        avl_debug( &test_tree );
#endif

        printf("\n");




        // debug test_tree2:

        printf("\navl_iterate( test_tree2 ):\n");
        i=0;
        an = NULL;
        while( (an = avl_iterate( &test_tree2, an ) ) ) {
                t = ((struct test_type*)(an->item));
                if ( i > t->test_key2)
                        printf("\nERROR %d > %d \n", i, t->test_key2);
                i = t->test_key2;
                printf( "%3d/%1d ", t->test_key2, t->w );
        }

        printf("\navl_next( test_tree2):\n");
        i = 0; j = 0;
        while( (an = avl_next( &test_tree2,  &j )) ) {
                t = ((struct test_type*)(an->item));
                j = t->test_key2;
                if ( i > t->test_key2)
                        printf("\nERROR %d > %d \n", i, t->test_key2);

                i = t->test_key2;

                printf( "N%4d/%1d ", t->test_key2, t->w );

                if ( i%10 == 0 )
                        printf("\n");

        }

#ifdef AVL_DEBUG
        printf("\navl_debug():\n");
        avl_debug( &test_tree2 );
#endif

        printf("\n");


        // remove whats left:

        while( test_tree.root ) {
                t = (struct test_type*)test_tree.root->item;
                avl_remove(&test_tree, &t->test_key, -300190);
                avl_remove(&test_tree2, &t->test_key2, -300191);
                printf(" removed %d/%d  %d/%d\n", t->test_key, t->v,  t->test_key2, t->w );
                debugFree( t, -300042 );
        }

        printf("\n");
        cleanup_all(CLEANUP_SUCCESS);
}


static int32_t tree_max = 5;
static int32_t opt_tree ( uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn ) {

	if ( cmd == OPT_APPLY )
		avl_test(tree_max);

	return SUCCESS;
}

static struct opt_type msg_options[]=
{
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help

	{ODI,0,"tree",  	        0, 9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&tree_max,	0,	        20,	        1,0,	        opt_tree,
			ARG_VALUE_FORM,	"show tree with given number of elements"}

};



#endif

void init_avl( void )
{
#ifdef AVL_TEST
	register_options_array( msg_options, sizeof( msg_options ), CODE_CATEGORY_NAME );
#endif

}
