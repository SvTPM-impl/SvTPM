#ifndef KBHITH
#define KBHITH

//extern "C" {

void init_keyboard(void);
void close_keyboard(void);
int kbhit(void);
int readch(void); 

void pauseLinux(void);

//}

#endif
