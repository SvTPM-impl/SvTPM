/*(Copyright)

        Microsoft Copyright 2009, 2010, 2011, 2012, 2013
        Confidential Information

*/

#ifndef     _BOOL_H
#define     _BOOL_H

#if defined(TRUE)
#undef TRUE
#endif


#if defined FALSE
#undef FALSE
#endif

typedef int BOOL;
#define FALSE   ((BOOL)0)
#define TRUE    ((BOOL)1)

#endif
