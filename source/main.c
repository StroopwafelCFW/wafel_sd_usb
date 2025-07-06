#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <wafel/dynamic.h>
#include <wafel/ios_dynamic.h>
#include <wafel/utils.h>
#include <wafel/patch.h>
#include <wafel/ios/svc.h>
#include <wafel/trampoline.h>
#include "wafel/ios/prsh.h"
#include "wafel/hai.h"
#include "rednand_config.h"
#include "sal_partition.h"
#include "sal_mbr.h"
#include "wfs.h"


// tells crypto to not do crypto (depends on stroopwafel patch)
#define NO_CRYPTO_HANDLE 0xDEADBEEF

static FSSALAttachDeviceArg extra_attach_arg;

static bool active = false;

void clone_patch_attach_usb_hanlde(FSSALAttachDeviceArg *attach_arg){
    memcpy(&extra_attach_arg, attach_arg, sizeof(extra_attach_arg));
    patch_partition_attach_arg(&extra_attach_arg, DEVTYPE_USB);
    // somehow it doesn't work if we fix the handle pointer
    //extra_server_handle[0x3] = (int) extra_server_handle;
    FSSALHandle res = FSSAL_attach_device(&extra_attach_arg);
    debug_printf("%s: Attached extra handle. res: 0x%X\n", PLUGIN_NAME, res);
}

void hai_write_file_patch(trampoline_t_state *s){
    uint32_t *buffer = (uint32_t*)s->r[1];
    debug_printf("HAI WRITE COMPANION\n");
    if(active && hai_getdev() == DEVTYPE_USB){
        hai_companion_add_offset(buffer, partition_offset);
    }
}

void hai_ios_patches(trampoline_t_state *s){
    if(active && hai_getdev() == DEVTYPE_USB)
        hai_redirect_mlc2sd();
}

int hai_path_sprintf_hook(char* parm1, char* parm2, char *fmt, char *dev, int (*sprintf)(char*, char*, char*, char*, char*), int lr, char *companion_file ){
    if(active)
        dev = "mlc";
    return sprintf(parm1, parm2, fmt, dev, companion_file);
}

void apply_hai_patches(void){
    trampoline_t_hook_before(0x050078AE, hai_write_file_patch);
    hai_apply_getdev_patch();
    //apply patches to HAI IOS just before it gets launched
    trampoline_t_hook_before(0x0500881e, hai_ios_patches);
    //force device in hai parm to MLC
    trampoline_t_blreplace(0x051001d6, hai_path_sprintf_hook);
    //ASM_T_PATCH_K(0x05100198, "nop");
}

void *sdusb_server_handle = 0;
void hook_register_sd(trampoline_state *state){
    FSSALAttachDeviceArg *attach_arg = (FSSALAttachDeviceArg*)state->r[0];

    int res = read_usb_partition_from_mbr(attach_arg, &partition_offset, &partition_size, NULL);
    if(res!=2)
        return;

    active = true;

    // the virtual USB device has to use the original slot, so the sd goes to the extra slot
    sdusb_server_handle = attach_arg->server_handle;
    clone_patch_attach_usb_hanlde(attach_arg);
}

static void wfs_initDeviceParams_exit_hook(trampoline_state *regs){
    WFS_Device *wfs_device = (WFS_Device*)regs->r[5];
    FSSALDevice *sal_device = FSSAL_LookupDevice(wfs_device->handle);
    void *server_handle = sal_device->server_handle;
    debug_printf("wfs_initDeviceParams_exit_hook server_handle: %p\n", server_handle);
    if(server_handle == sdusb_server_handle) {
#ifdef USE_MLC_KEY
        wfs_device->crypto_key_handle = WFS_KEY_HANDLE_MLC;
#else
        wfs_device->crypto_key_handle = WFS_KEY_HANDLE_NOCRYPTO;
#endif
    }
}

// This fn runs before everything else in kernel mode.
// It should be used to do extremely early patches
// (ie to BSP and kernel, which launches before MCP)
// It jumps to the real IOS kernel entry on exit.
__attribute__((target("arm")))
void kern_main()
{
    // Make sure relocs worked fine and mappings are good
    debug_printf("we in here %s plugin kern %p\n", PLUGIN_NAME, kern_main);

    debug_printf("init_linking symbol at: %08x\n", wafel_find_symbol("init_linking"));

    rednand_config *rednand_conf;
    size_t rednand_conf_size;
    if(!prsh_get_entry("rednand", (void**)&rednand_conf, &rednand_conf_size)){
        if(rednand_conf_size<sizeof(rednand_config_v1) || rednand_conf->mlc.lba_length){
            debug_printf("%s: detected MLC redirection, %s will be disabled\n", PLUGIN_NAME, PLUGIN_NAME);
            return;
        }
    }

    trampoline_hook_before(0x107435f4, wfs_initDeviceParams_exit_hook);

    trampoline_hook_before(0x107bd9a4, hook_register_sd);

    // somehow it causes crashes when applied from the attach hook
    apply_hai_patches();

    debug_printf("%s: patches applied\n", PLUGIN_NAME);

    //trampoline_hook_before(0x10740f2c, test_hook);
}

// This fn runs before MCP's main thread, and can be used
// to perform late patches and spawn threads under MCP.
// It must return.
void mcp_main()
{

}
