#include "hiber.h"

EFI_HANDLE IH;
EFI_SYSTEM_TABLE *ST;
EFI_BOOT_SERVICES *BS;
EFI_RUNTIME_SERVICES *RS;
SIMPLE_TEXT_OUTPUT_INTERFACE *conout;
bool boot_services_active;

bool shelled;
CHAR16 *hiber_img_path;
EFI_FILE_PROTOCOL *hiber_img;
EFI_SHELL_PROTOCOL *esp;
SHELL_FILE_HANDLE hiber_img_shell;

static void
efi_exit(EFI_STATUS exit_code)
{
	if (boot_services_active) {
//		BS->FreePages(heap, EFI_SIZE_TO_PAGES(heapsize));
		BS->Exit(IH, exit_code, 0, NULL);
	} else {
		RS->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
	}
	__unreachable();
}

static bool
hiber_open_img_boot(void)
{
	static EFI_GUID sfsp_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
	EFI_FILE_PROTOCOL *root;
	EFI_HANDLE *handles;
	UINTN handle_count, i;
	CHAR16 *dev __unused, *path;
	EFI_STATUS status;
	bool res;

	res = false;
	dev = path = NULL;

	handles = NULL;
	handle_count = 0;
	status = BS->LocateHandleBuffer(ByProtocol, &sfsp_guid, NULL,
	    &handle_count, &handles);
	if (status != EFI_SUCCESS) {
		hiber_printf("LocateHandle for EFI_SIMPLE_FILE_SYSTEM_PROTOCOL "
		    "failed, status %d\n", status);
		return (false);
	}

	fs = NULL;
	for (i = 0; i < handle_count; i++) {
	}

	if (fs == NULL) {
		hiber_printf("XXX");
		goto close_handles;
	}

	root = NULL;
	status = fs->OpenVolume(fs, &root);
	if (status != EFI_SUCCESS) {
		hiber_printf("Cannot open volume %s\n", "XXX");
		goto close_handles;
	}

	status = root->Open(root, &hiber_img, path, EFI_FILE_MODE_READ,
	    EFI_FILE_READ_ONLY | EFI_FILE_HIDDEN | EFI_FILE_SYSTEM);
	if (status != EFI_SUCCESS) {
		hiber_printf("Cannot open volume %s\n", "XXX");
		goto close_volume;
	}
	res = true;
	hiber_printf("Opened %s using FILE_SYSTEM_PROTOCOL, handle %p\n",
	    "XXX", hiber_img);

close_volume:
	;// XXX

close_handles:
	;// XXX

	return (res);
}

static bool
hiber_open_img_shell(void)
{
	static EFI_GUID esp_guid = EFI_SHELL_PROTOCOL_GUID;
	EFI_HANDLE *handles;
	UINTN handles_size, i;
	EFI_STATUS status;
	bool res;

	handles = NULL;
	handles_size = 0;
	res = false;

	status = BS->LocateHandle(ByProtocol, &esp_guid, NULL, &handles_size,
	    handles);
	if (status != EFI_BUFFER_TOO_SMALL) {
		hiber_printf("Cannot get handles storage size "
		    "for EFI_SHELL_PROTOCOL_GUID, status %d\n", status);
		goto done;
	}
	status = BS->AllocatePool(EfiBootServicesData, handles_size,
	    (void *)&handles);
	if (status != EFI_SUCCESS) {
		hiber_printf("Cannot allocate %u bytes for shell handles, "
		    "status %d\n", handles_size, status);
		goto done;
	}
	status = BS->LocateHandle(ByProtocol, &esp_guid, NULL, &handles_size,
	    handles);
	if (status != EFI_SUCCESS) {
		hiber_printf("Cannot locate EFI_SHELL_PROTOCOL handles, "
		    "status %d\n", status);
		goto free_pool;
	}

	for (i = 0 ; i < handles_size / sizeof(EFI_HANDLE); i++) {
		status = BS->OpenProtocol(handles[i], &esp_guid,
		    (VOID **)&esp, IH, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
		if (status == EFI_SUCCESS)
			break;
	}
	if (i == handles_size / sizeof(EFI_HANDLE)) {
		hiber_printf("Cannot find EFI_SHELL_PROTOCOL\n");
		goto free_pool;
	}

	status = esp->OpenFileByName(hiber_img_path, &hiber_img_shell,
	    EFI_FILE_MODE_READ);
	if (status != EFI_SUCCESS) {
		hiber_printf("Shell cannot open %S, status %d",
		    hiber_img_path, status);
		goto free_pool;
	}
	res = true;
	hiber_printf("Opened %S using SHELL_PROTOCOL, handle %p\n",
	    hiber_img_path, hiber_img_shell);

free_pool:
	BS->FreePool(handles);
done:
	return (res);
}

static bool
hiber_read_img_shell(uint64_t offset, void *buf, unsigned sz)
{
	UINTN sz1;
	EFI_STATUS status;

	status = esp->SetFilePosition(hiber_img_shell, offset);
	if (status != EFI_SUCCESS) {
		hiber_printf("hiber_read_img_shell set pos failed, status %d\n",
		    status);
		return (false);
	}
	sz1 = sz;
	status = esp->ReadFile(hiber_img_shell, &sz1, buf);
	if (status != EFI_SUCCESS) {
		hiber_printf("hiber_read_img_shell failed, status %d\n",
		    status);
		return (false);
	} else if (sz != sz1) {
		hiber_printf("hiber_read_img_shell short read\n");
		return (false);
	}
	return (true);
}

static bool
hiber_read_img_boot(uint64_t offset, void *buf, unsigned sz)
{
	UINTN sz1;
	EFI_STATUS status;

	status = hiber_img->SetPosition(hiber_img, offset);
	if (status != EFI_SUCCESS) {
		hiber_printf("hiber_read_img_boot set pos failed, status %d\n",
		    status);
		return (false);
	}
	sz1 = sz;
	status = hiber_img->Read(hiber_img, &sz1, buf);
	if (status != EFI_SUCCESS) {
		hiber_printf("hiber_read_img_boot failed, status %d\n",
		    status);
		return (false);
	} else if (sz != sz1) {
		hiber_printf("hiber_read_img_boot short read\n");
		return (false);
	}
	return (true);
}

bool
hiber_read_img(uint64_t offset, void *buf, unsigned sz)
{
	if (shelled)
		return (hiber_read_img_shell(offset, buf, sz));
	return (hiber_read_img(offset, buf, sz));
}

static void
hiber_restore(void)
{
	// XXX bread and meat
}

EFI_STATUS
efi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table)
{
	static EFI_GUID loaded_image_proto = LOADED_IMAGE_PROTOCOL;
	static EFI_GUID shell_parameters_proto =
	    EFI_SHELL_PARAMETERS_PROTOCOL_GUID;
	EFI_LOADED_IMAGE *loaded_image;
	EFI_SHELL_PARAMETERS_PROTOCOL *shell_params;
	EFI_STATUS status;
	int exit_status;

	IH = image_handle;
	ST = system_table;
	BS = ST->BootServices;
	RS = ST->RuntimeServices;
	conout = ST->ConOut;
	boot_services_active = true;

	hiber_printf("Hello\n");

	status = BS->OpenProtocol(image_handle, &loaded_image_proto,
	    (void **)&loaded_image, image_handle, NULL,
	    EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
	if (status != EFI_SUCCESS)
		hiber_printf("cannot get loaded_image, status %d\n", status);

	exit_status = 0;

	status = BS->OpenProtocol(image_handle, &shell_parameters_proto,
	    (void **)&shell_params, image_handle, NULL,
	    EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
	if (status == EFI_SUCCESS) {
		if (shell_params->Argc != 2) {
			hiber_printf("Usage: hiber <EFI path>\n");
			exit_status = 1;
		} else {
			hiber_img_path = shell_params->Argv[1];
			if (!hiber_open_img_shell())
				exit_status = 1;
			shelled = true;
		}
	} else if (status == EFI_UNSUPPORTED) {
		if (!hiber_open_img_boot())
			exit_status = 1;
	} else {
		hiber_printf("cannot get shell_params, status %d\n", status);
		exit_status = 1;
	}

	if (exit_status == 0) {
		if (hiber_check_format())
			hiber_restore();
	}

	efi_exit(exit_status);
	return (exit_status);
}
