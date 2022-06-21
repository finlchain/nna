/**
    @file list.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;


void list_init (LIST_T *p_list)
{
    pthread_mutex_lock (&list_mutex);
    
    p_list->head = p_list->tail = NULL;
    p_list->num_items = 0;

    pthread_mutex_unlock (&list_mutex);
}

int32_t list_get_num_of_list (LIST_T *p_list)
{
    return (p_list->num_items);
}

bool list_is_empty (LIST_T *p_list)
{
    if( p_list->head == NULL ) {
        return (true);
    }

    return (false);
}

// Insert item to tail
void list_insert (LIST_T *p_list, LIST_ITEM_T *p_item)
{
    pthread_mutex_lock (&list_mutex);

    p_list->num_items++;

    p_item->next = NULL;

    if( p_list->tail != NULL) {
        p_item->prev = p_list->tail;
        p_list->tail->next = p_item;
    }
    else {
        p_item->prev = NULL;
        p_list->head = p_item;
    }

    p_list->tail = p_item;

    pthread_mutex_unlock (&list_mutex);
}

// Remove item from head
LIST_ITEM_T *list_remove (LIST_T *p_list)
{
    LIST_ITEM_T *p_item;

    pthread_mutex_lock (&list_mutex);

    if( p_list->tail == NULL )
    {
        pthread_mutex_unlock (&list_mutex);
        return NULL;
    }

    if( p_list->num_items == 0 )
    {
        pthread_mutex_unlock (&list_mutex);
        return NULL;
    }

    ASSERT_M(p_list->num_items);

    p_list->num_items--;

    p_item = p_list->head;

    ASSERT_M(p_item);

    if( p_list->head ) {
        p_list->head = p_list->head->next;

        if( p_list->head == NULL ) {
            p_list->tail = NULL;
        }
        else {
            p_list->head->prev = NULL;
        }

        p_item->prev = NULL;
        p_item->next = NULL;
    }

    pthread_mutex_unlock (&list_mutex);

    return (p_item);
}

void list_remove_item (LIST_T *p_list, LIST_ITEM_T *p_item)
{
    LIST_ITEM_T *p_fix_item, *p_cur_item;

    if (p_list->num_items == 0)
    {
        return;
    }

    pthread_mutex_lock (&list_mutex);
    
    p_cur_item = p_list->head;
    while (p_cur_item)
    {
        if (p_cur_item == p_item)
        {
            if (p_item->prev != NULL)
            {
                p_fix_item = p_item->prev;

                p_fix_item->next = p_item->next;
            }
            else
            {
                p_list->head = p_item->next;
            }

            if (p_item->next != NULL)
            {
                p_fix_item = p_item->next;

                p_fix_item->prev = p_item->prev;
            }
            else
            {
                p_list->tail = p_item->prev;
            }

            p_list->num_items--;

            break;
        }

        p_cur_item = p_cur_item->next;
    }

    pthread_mutex_unlock (&list_mutex);
}

LIST_ITEM_T *list_get_head (LIST_T *p_list)
{
    LIST_ITEM_T *p_item;

    p_item = p_list->head;

    return (p_item);
}

