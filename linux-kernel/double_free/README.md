# Collections of query spotting double-frees

| CVE            | Impact                | Query                          | Fix                                                                                                                                   |
|:--------------:|:---------------------:|:------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2022-29156 | Possible LPE | weggli '{<br>struct _ * $dev;<br>$dev->dev.release = _ ;<br>if (_){<br>put_device(&$dev->dev);<br>NOT: $dev = NULL;<br>goto _;<br>}<br>kfree($dev);<br>}' drivers/ | [RDMA/rtrs-clt: Fix possible double free in error case](https://github.com/torvalds/linux/commit/8700af2cc18c919b2a83e74e0479038fd113c15d) |



## CVE-2022-29156
drivers/infiniband/ulp/rtrs/rtrs-clt.c in the Linux kernel before 5.16.12 has a double free related to 
rtrs_clt_dev_release.

```sh
weggli '{
        struct _* $dev;
        $dev->dev.release = _;
        if (_){
                put_device(&$dev->dev);
                NOT: $dev = NULL;
                goto _;
        }

        kfree($dev);
}' drivers/
 ```
```c
[...]
kernel/drivers/infiniband/ulp/rtrs/rtrs-clt.c:2522                                                                                                                                                               
static struct rtrs_clt *alloc_clt(const char *sessname, size_t paths_num,                                                                                                                                                                    
                                  u16 port, size_t pdu_sz, void *priv,                                                                                                                                                                       
..                                                                                                                                                                                                                                           
                                  unsigned int max_segments,                                                                                                                                                                                 
                                  size_t max_segment_size,                                                                                                                                                                                   
                                  unsigned int reconnect_delay_sec,                                                                                                                                                                          
                                  unsigned int max_reconnect_attempts)                                                                                                                                                                       
{                                                                                                                                                                                                                                            
        struct rtrs_clt *clt;                                                                                                                                                                                                                
        int err;                                                                                                                                                                                                                             
                                                                                                                                                                                                                                             
        if (!paths_num || paths_num > MAX_PATHS_NUM)                                                                                                                                                                                         
                return ERR_PTR(-EINVAL);                                                                                                                                                                                                     
                                                                                                                                                                                                                                             
..                                                                                                                                                                                                                                           
        init_waitqueue_head(&clt->permits_wait);                                                                                                                                                                                             
        mutex_init(&clt->paths_ev_mutex);                                                                                                                                                                                                    
        mutex_init(&clt->paths_mutex);                                                                                                                                                                                                       
                                                                                                                                                                                                                                             
        clt->dev.class = rtrs_clt_dev_class;                                                                                                                                                                                                 
        clt->dev.release = rtrs_clt_dev_release; /* rtrs_clt_dev_release() calls kfree(clt) */                                                                                                                                                                                           
        err = dev_set_name(&clt->dev, "%s", sessname);                                                                                                                                                                                       
        if (err)                                                                                                                                                                                                                             
                goto err;                                                                                                                                                                                                                    
        /*                                                                                                                                                                                                                                   
         * Suppress user space notification until                                                                                                                                                                                            
         * sysfs files are created                                                                                                                                                                                                           
         */                                                                                                                                                                                                                                  
        dev_set_uevent_suppress(&clt->dev, true);                                                                                                                                                                                            
        err = device_register(&clt->dev);                                                                                                                                                                                                    
        if (err) {                                                                                                                                                                                                                           
                put_device(&clt->dev); /* put_device calls release() if &clt->dev's refcount == 0 - first free */                                                                                                                                                                                                    
                goto err;                                                                                                                                                                                                                    
        }                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                             
        clt->kobj_paths = kobject_create_and_add("paths", &clt->dev.kobj);                                                                                                                                                                   
        if (!clt->kobj_paths) {                                                                                                                                                                                                              
                err = -ENOMEM;                                                                                                                                                                                                               
..                                                                                                                                                                                                                                           
        return clt;                                                                                                                                                                                                                          
err_dev:                                                                                                                                                                                                                                     
        device_unregister(&clt->dev);                                                                                                                                                                                                        
err:                                                                                                                                                                                                                                         
        free_percpu(clt->pcpu_path);                                                                                                                                                                                                         
        kfree(clt);  /* second free */                                                                                                                                                                                                                        
        return ERR_PTR(err);                                                                                                                                                                                                                 
}
[...]
```