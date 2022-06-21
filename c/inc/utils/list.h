/**
    @file list.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/


#ifndef __LIST_H__
#define __LIST_H__

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct LIST_ITEM_ST {
    struct LIST_ITEM_ST *prev;
    struct LIST_ITEM_ST *next;
} LIST_ITEM_T, *PLIST_ITEM_T;

typedef struct LIST_ST {
    PLIST_ITEM_T head;
    PLIST_ITEM_T tail;
    int32_t num_items;
} LIST_T, *PLIST_T;


void list_init (LIST_T *pList);
int32_t list_get_num_of_list (LIST_T *pList);
bool list_is_empty (LIST_T *pList);
void list_insert (LIST_T *pList, LIST_ITEM_T *p_item);
LIST_ITEM_T *list_remove (LIST_T *pList);
void list_remove_item (LIST_T *p_list, LIST_ITEM_T *p_item);
LIST_ITEM_T *list_get_head (LIST_T *pList);


#ifdef __cplusplus
}
#endif

#endif /* __LIST_H__ */

