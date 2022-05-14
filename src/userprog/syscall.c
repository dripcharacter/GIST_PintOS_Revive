#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"

void user_vaddr_cond(const void *vaddr)
{
  if(!is_user_vaddr(vaddr))
    exit(-1);
}

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  switch(*(uint32_t*)f->esp)
  {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      user_vaddr_cond(f->esp + 4);
      exit(*(uint32_t *)(f->esp + 4));
      break;
    case SYS_EXEC:
      user_vaddr_cond(f->esp + 4);
      f->eax=exec((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_WAIT:
      user_vaddr_cond(f->esp + 4);
      f->eax = wait ((pid_t *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CREATE:
      user_vaddr_cond(f->esp + 4);
      user_vaddr_cond(f->esp + 8);
      f->eax=create((const char *)*(uint32_t *)(f->esp + 4), (const char *)*(uint32_t *)(f->esp + 8));
      break;
    case SYS_REMOVE:
      user_vaddr_cond(f->esp + 4);
      f->eax=remove((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_OPEN:
      user_vaddr_cond(f->esp + 4);
      f->eax=open((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_FILESIZE:
      user_vaddr_cond(f->esp + 4);
      f->eax=filesize((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_READ:
      user_vaddr_cond(f->esp + 4);
      user_vaddr_cond(f->esp + 8);
      user_vaddr_cond(f->esp + 12);
      f->eax=read((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*(uint32_t *)(f->esp + 12));
      break;
    case SYS_WRITE:
      user_vaddr_cond(f->esp + 4);
      user_vaddr_cond(f->esp + 8);
      user_vaddr_cond(f->esp + 12);
      f->eax=write((int)*(uint32_t *)(f->esp + 4), (const void *)*(uint32_t *)(f->esp + 8), (unsigned)*(uint32_t *)(f->esp + 12));
      break;
    case SYS_SEEK:
      user_vaddr_cond(f->esp + 4);
      user_vaddr_cond(f->esp + 8);
      f->eax=seek((int)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;
    case SYS_TELL:
      user_vaddr_cond(f->esp + 4);
      f->eax=tell((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CLOSE:
      user_vaddr_cond(f->esp + 4);
      f->eax=close((int)*(uint32_t *)(f->esp + 4));
      break;
  }
  //printf ("system call!\n");
  //thread_exit ();
}

void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  struct thread *cur_thread=thread_current();
  cur_thread->exit_status=status;
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit();
}

pid_t exec(const char *file)
{
  return process_execute(file);
}

int wait(pid_t pid)
{
  //TODO: we have to implement process_wait later!!!
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size)
{
  if(file!=NULL)
    return filesys_create(file, initial_size);
  else
    exit(-1);
}

bool remove(const char *file)
{
  if(file!=NULL)
    return filesys_remove(file, initial_size);
  else
    exit(-1);
}

int open(const char *file)
{
  
}

int filesize(int fd)
{
  
}

int read(int fd, void *buffer, unsigned length)
{
  
}

int write(int fd, const void *buffer, unsigned length)
{
  
}

void seek(int fd, unsigned position)
{

}

unsigned tell(int fd)
{
  
}

void close(int fd)
{
  
}
