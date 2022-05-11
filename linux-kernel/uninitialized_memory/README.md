# Collections of query spotting uninitialized memory in the kernel

| CVE            | Impact                | Query                          | Fix                                                                                                                                   |
|:--------------:|:---------------------:|:------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2022-29968 | Kernel heap info leak |  weggli -R func=init '_ $func(_){<br>struct _* $s = _;<br>NOT: kzalloc($d, _);<br>NOT: memset($d, 0, _);<br>}' fs/io_uring.c  | [io_uring: fix uninitialized field in rw io_kiocb](https://github.com/torvalds/linux/commit/32452a3eb8b64e01e2be717f518c0be046975b9d) |



## CVE-2022-29968

An issue was discovered in the Linux kernel through 5.17.5. io_rw_init_file in
fs/io_uring.c lacks initialization of kiocb->private.

```sh
$ weggli -R func=init '_ $func(_
    struct _* $s = _;
    NOT: kzalloc($d, _);
    NOT: memset($d, 0, _);
  }' fs/io_uring.c
 ```
```c
[...]
kernel/fs/io_uring.c:3755
static int io_rw_init_file(struct io_kiocb *req, fmode_t mode) /* kiocb->private init missing in this function */
{
        struct kiocb *kiocb = &req->rw.kiocb;
        struct io_ring_ctx *ctx = req->ctx;
        struct file *file = req->file;
        int ret;

        if (unlikely(!file || !(file->f_mode & mode)))
                return -EBADF;

[...]
```
