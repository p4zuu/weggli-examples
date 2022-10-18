# Collection of queries spotting use-after-frees

| CVE            | Impact                | Fix                                                                                                                                   |
|:--------------:|:---------------------:|---------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2022-3545 | Possible LPE |  [nfp: fix use-after-free in area_cache_get()](https://git.kernel.org/pub/scm/linux/kernel/git/klassert/ipsec-next.git/commit/?id=02e1a114fdb71e59ee6770294166c30d437bf86a) |



## CVE-2022-3545
Affected by this vulnerability is the function area_cache_get of the file
drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the component IPsec.
The manipulation leads to use after free.

```sh
weggli -R init=_init '
_ $func(_ id) {
        struct _* $cache; 
        $cache->id = $id; 
        $err = $init(_); 
        if ($err < 0){
                return _;
        }
}' ./drivers
 ```

```c
kernel/drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c:822                                                            
static struct nfp_cpp_area_cache *                                                                                                                           
area_cache_get(struct nfp_cpp *cpp, u32 id,                                                                                                                  
               u64 addr, unsigned long *offset, size_t length)                                                                                               
{                                                                                                                                                            
        struct nfp_cpp_area_cache *cache;                                                                                                                    
        int err;                                                                                                                                             
                                                                                                                                                             
        /* Early exit when length == 0, which prevents                                                                                                       
         * the need for special case code below when                                                                                                         
         * checking against available cache size.                                                                                                            
..                                                                                                                                                           
                cache->id = 0;                                                                                                                               
                cache->addr = 0;                                                                                                                             
        }                                                                                                                                                    
                                                                                                                                                             
        /* Adjust the start address to be cache size aligned */                                                                                              
        cache->id = id;      // cache->id is set first                                                                                                                                 
        cache->addr = addr & ~(u64)(cache->size - 1);                                                                                                        
                                                                                                                                                             
        /* Re-init to the new ID and address */                                                                                                              
        if (cpp->op->area_init) {                                                                                                                            
                err = cpp->op->area_init(cache->area,                                                                                                        
                                         id, cache->addr, cache->size);                                                                                      
                if (err < 0)  // first uaf scenario on error: cache->id is valid but refcount is 0 on error
                {                                                                                                                               
                        mutex_unlock(&cpp->area_cache_mutex);                                                                                                
                        return NULL;                                                                                                                         
                }                                                                                                                                            
        }                                                                                                                                                    
                                                                                                                                                             
        /* Attempt to acquire */                                                                                                                             
        err = nfp_cpp_area_acquire(cache->area);                                                                                                             
..                                                                                                                                                           
} 
drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c:822
static struct nfp_cpp_area_cache *
area_cache_get(struct nfp_cpp *cpp, u32 id,
               u64 addr, unsigned long *offset, size_t length)
{
        struct nfp_cpp_area_cache *cache;
        int err;

        /* Early exit when length == 0, which prevents
         * the need for special case code below when
         * checking against available cache size.
..
                cache->id = 0;
                cache->addr = 0;
        }

        /* Adjust the start address to be cache size aligned */
        cache->id = id;
        cache->addr = addr & ~(u64)(cache->size - 1);

        /* Re-init to the new ID and address */
        if (cpp->op->area_init) {
                err = cpp->op->area_init(cache->area,
                                         id, cache->addr, cache->size);
                if (err < 0) { 
                        mutex_unlock(&cpp->area_cache_mutex);
                        return NULL;
                }
        }

        /* Attempt to acquire */
        err = nfp_cpp_area_acquire(cache->area);
        if (err < 0) {  // second uaf scenario on error
                mutex_unlock(&cpp->area_cache_mutex);
                return NULL;
        }

exit:
        /* Adjust offset */
        *offset = addr - cache->addr;
..
}
```