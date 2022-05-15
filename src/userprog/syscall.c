#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "devices/block.h"

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
  //printf("syscall : %d\n",*(uint32_t *)(f->esp));
  switch(*(uint32_t*)(f->esp))
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
      f->eax = wait ((pid_t)*(int *)(f->esp + 4));
      break;
    case SYS_CREATE:
      user_vaddr_cond(f->esp + 4);
      user_vaddr_cond(f->esp + 8);
      f->eax=create((const char *)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
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
      seek((int)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;
    case SYS_TELL:
      user_vaddr_cond(f->esp + 4);
      f->eax=tell((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CLOSE:
      user_vaddr_cond(f->esp + 4);
      close((int)*(uint32_t *)(f->esp + 4));
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
  int tmp_idx;
  for(tmp_idx=3; tmp_idx<128; tmp_idx++)
  {
    if(cur_thread->fd[tmp_idx] != NULL)
      close(tmp_idx);
  }
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit();
}

pid_t exec(const char *file)
{
  return process_execute(file);
}

int wait(pid_t pid)
{
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
    return filesys_remove(file);
  else
    exit(-1);
}

int open(const char *file)
{
  user_vaddr_cond(file);
  if(file==NULL)
    exit(-1);
  struct file *new_file=filesys_open(file);
  if(new_file==NULL)
    return -1;
  else
  {
    int tmp_fd;
    for(tmp_fd=3; tmp_fd<128; tmp_fd++)
    {
      if(thread_current()->fd[tmp_fd]==NULL)
      {
        if(strcmp(thread_current()->name, file)==false)
          file_deny_write(new_file);
        thread_current()->fd[tmp_fd]=new_file;
        return tmp_fd;
      }
    }
  }
}

int filesize(int fd)
{
  if(thread_current()->fd[fd] != NULL)
    return file_length(thread_current()->fd[fd]);
  else
    exit(-1);
}

int read(int fd, void *buffer, unsigned size)
{
  user_vaddr_cond(buffer);
  if(fd==0)
  {
    unsigned tmp_stdin_idx;
    char *cur_buf_ptr=buffer;
    for(tmp_stdin_idx=0; tmp_stdin_idx<size; tmp_stdin_idx++)
    {
      char tmp_input=input_getc();
      *cur_buf_ptr=tmp_input;
      cur_buf_ptr++;
      if(tmp_input=='\0')
        break;
    }
    return tmp_stdin_idx;
  }
  else
  {
    struct file *file_for_read=thread_current()->fd[fd];
    if(file_for_read==NULL)
      exit(-1);
    else
      return file_read(file_for_read, buffer, size);
  }
}

int write(int fd, const void *buffer, unsigned size)
{
  user_vaddr_cond(buffer);
  if(fd==1)
  {
    putbuf(buffer, size);
    return size;
  }
  else
  {
    struct file *file_for_write=thread_current()->fd[fd];
    if(file_for_write==NULL)
      exit(-1);
    if(file_for_write->deny_write)
      file_deny_write(file_for_write);
    return file_write(file_for_write, buffer, size);
  }
}

void seek(int fd, unsigned position)
{
  struct file *file_for_seek=thread_current()->fd[fd];
  if(file_for_seek==NULL)
    exit(-1);
  else
    return file_seek(file_for_seek, position);
}

unsigned tell(int fd)
{
  struct file *file_for_tell=thread_current()->fd[fd];
  if(file_for_tell==NULL)
    exit(-1);
  else
    return file_tell(file_for_tell);
}

void close(int fd)
{
  struct file *file_for_close=thread_current()->fd[fd];
  if(file_for_close==NULL)
    exit(-1);
  else
  {
    thread_current()->fd[fd]=NULL;
    file_close(file_for_close);
  }
}
