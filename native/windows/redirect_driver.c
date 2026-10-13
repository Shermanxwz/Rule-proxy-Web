// Build-only, unsigned ALE_CONNECT_REDIRECT foundation. Not a product driver.
// No driver load, test-signing change, global routes or WinDivert exception.
#pragma warning(push)
// The published WDK uses anonymous unions and alignment padding in its ABI.
#pragma warning(disable: 4201 4324)
#include <ntifs.h>
#include <initguid.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <wdmsec.h>
#include "redirect_protocol.h"
#pragma warning(pop)

C_ASSERT(sizeof(RP_REDIRECT_CONTEXT) == RP_CONTEXT_BYTES);
C_ASSERT(sizeof(RP_RELAY_CONFIG) == RP_CONFIG_BYTES);
#define RP_POOL_TAG 'drPR'

static PDEVICE_OBJECT RpDevice;
static HANDLE RpRedirectHandle;
static UINT32 RpCalloutIds[2];
static KSPIN_LOCK RpLock;
static RP_RELAY_CONFIG RpConfig;
static PEPROCESS RpRelayProcess;
static BOOLEAN RpRelayAlive;
static EX_RUNDOWN_REF RpRundown;
static BOOLEAN RpNotifyRegistered;
static UNICODE_STRING RpSymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\RuleProxyAleRedirect");

static VOID RpBlock(FWPS_CLASSIFY_OUT0* result)
{
    // A callout may veto even if another provider cleared ACTION_WRITE.
    result->actionType = FWP_ACTION_BLOCK;
    result->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static VOID RpProcessNotify(PEPROCESS process, HANDLE processId, PPS_CREATE_NOTIFY_INFO createInfo)
{
    KIRQL irql;
    UNREFERENCED_PARAMETER(processId);
    if (createInfo != NULL) return;
    KeAcquireSpinLock(&RpLock, &irql);
    if (process == RpRelayProcess) RpRelayAlive = FALSE;
    KeReleaseSpinLock(&RpLock, irql);
}

static NTSTATUS RpNotify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* key, FWPS_FILTER1* filter)
{
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(key);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static VOID RpRedirectClassify(const FWPS_INCOMING_VALUES0* values,
                               const FWPS_INCOMING_METADATA_VALUES0* metadata,
                               VOID* layerData, const VOID* classifyContext,
                               const FWPS_FILTER1* filter, UINT64 flowContext,
                               FWPS_CLASSIFY_OUT0* result)
{
    const UINT32 entryRights = result->rights;
    RP_RELAY_CONFIG config;
    KIRQL irql;
    BOOLEAN active;
    UINT64 handle = 0;
    NTSTATUS status;
    FWPS_CONNECT_REQUEST0* request = NULL;
    FWPS_CONNECT_REQUEST0 originalRequest = { 0 };
    RP_REDIRECT_CONTEXT* context = NULL;
    UINT16 family;
    FWP_VALUE0 protocol;
    FWPS_CONNECTION_REDIRECT_STATE state;
    VOID* priorContext = NULL;
    UNREFERENCED_PARAMETER(flowContext);
    RpBlock(result);
    if (!ExAcquireRundownProtection(&RpRundown)) return;
    if (!(entryRights & FWPS_RIGHT_ACTION_WRITE)) goto done;
    if (values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4) {
        family = RP_AF_INET;
        protocol = values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value;
    } else if (values->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6) {
        family = RP_AF_INET6;
        protocol = values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL].value;
    } else goto done;
    if (protocol.type != FWP_UINT8 || protocol.uint8 != IPPROTO_TCP || layerData == NULL ||
        filter->context == 0 || !(metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) goto done;
    KeAcquireSpinLock(&RpLock, &irql);
    active = RpRelayAlive;
    config = RpConfig;
    KeReleaseSpinLock(&RpLock, irql);
    // Relay exit invalidates subsequent configuration snapshots. The process
    // object is referenced until replacement; in-flight/PID-reuse races still
    // require live driver validation before this foundation is admitted.
    if (!active || metadata->processId == config.processId) goto done;
    state = FWPS_CONNECTION_NOT_REDIRECTED;
    if (metadata->currentMetadataValues & FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE)
        state = FwpsQueryConnectionRedirectState0(metadata->redirectRecords, RpRedirectHandle, &priorContext);
    if (state == FWPS_CONNECTION_REDIRECTED_BY_SELF || state == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF) {
        const RP_REDIRECT_CONTEXT* prior = (const RP_REDIRECT_CONTEXT*)priorContext;
        if (prior == NULL || prior->magic != RP_REDIRECT_MAGIC || prior->version != RP_REDIRECT_ABI ||
            prior->size != RP_CONTEXT_BYTES || prior->session != filter->context ||
            RtlCompareMemory(prior->generation, config.generation, 16) != 16) goto done;
        result->actionType = FWP_ACTION_PERMIT;
        result->rights = entryRights; // soft permit; the independent guard still arbitrates.
        goto done;
    }
    // Unknown/other redirectors are refused rather than chaining by assumption.
    if (state != FWPS_CONNECTION_NOT_REDIRECTED) goto done;
    status = FwpsAcquireClassifyHandle0((VOID*)classifyContext, 0, &handle);
    if (!NT_SUCCESS(status)) goto done;
    // AcquireWritableLayerData modifies result; reestablish fail-closed on all
    // failure paths and release the classify handle exactly once.
    result->rights = entryRights;
    status = FwpsAcquireWritableLayerDataPointer0(handle, filter->filterId, 0, (VOID**)&request, result);
    if (!NT_SUCCESS(status) || request == NULL) { request = NULL; goto failed; }
    originalRequest = *request;
    if (request->remoteAddressAndPort.ss_family != family || request->localRedirectContext != NULL ||
        request->localRedirectHandle != NULL) goto failed;
    context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*context), RP_POOL_TAG);
    if (context == NULL) goto failed;
    RtlZeroMemory(context, sizeof(*context));
    context->magic = RP_REDIRECT_MAGIC;
    context->version = RP_REDIRECT_ABI;
    context->size = (UINT32)sizeof(*context);
    context->family = family;
    context->session = filter->context;
    context->originalProcessId = metadata->processId;
    RtlCopyMemory(context->generation, config.generation, sizeof(context->generation));
    if (family == RP_AF_INET) {
        SOCKADDR_IN* destination = (SOCKADDR_IN*)&request->remoteAddressAndPort;
        context->destinationPort = RtlUshortByteSwap(destination->sin_port);
        RtlCopyMemory(context->destinationAddress, &destination->sin_addr, 4);
        RtlZeroMemory(destination, sizeof(*destination));
        destination->sin_family = AF_INET;
        destination->sin_addr.S_un.S_addr = RtlUlongByteSwap(0x7f000001u);
        destination->sin_port = RtlUshortByteSwap(config.ipv4Port);
    } else {
        SOCKADDR_IN6* destination = (SOCKADDR_IN6*)&request->remoteAddressAndPort;
        // Link-local scope is not expressible in a SOCKS5 IPv6 CONNECT.
        if (destination->sin6_scope_id != 0) goto failed;
        context->destinationPort = RtlUshortByteSwap(destination->sin6_port);
        RtlCopyMemory(context->destinationAddress, &destination->sin6_addr, 16);
        RtlZeroMemory(destination, sizeof(*destination));
        destination->sin6_family = AF_INET6;
        destination->sin6_addr.u.Byte[15] = 1;
        destination->sin6_port = RtlUshortByteSwap(config.ipv6Port);
    }
    if (context->destinationPort == 0) goto failed;
    request->localRedirectTargetPID = (DWORD)config.processId;
    request->localRedirectHandle = RpRedirectHandle;
    request->localRedirectContext = context;
    request->localRedirectContextSize = sizeof(*context);
    FwpsApplyModifiedLayerData0(handle, request, 0);
    request = NULL;
    // WFP owns and frees localRedirectContext after successful application.
    context = NULL;
    result->actionType = FWP_ACTION_PERMIT;
    result->rights = entryRights;
    goto done;
failed:
    if (request != NULL) {
        *request = originalRequest;
        FwpsApplyModifiedLayerData0(handle, request, 0);
    }
    RpBlock(result);
done:
    if (context != NULL) ExFreePoolWithTag(context, RP_POOL_TAG);
    if (handle != 0) FwpsReleaseClassifyHandle0(handle);
    ExReleaseRundownProtection(&RpRundown);
}

static NTSTATUS RpComplete(PIRP irp, NTSTATUS status)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS RpDispatchInner(PDEVICE_OBJECT device, PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    PEPROCESS process = NULL, previous = NULL;
    RP_RELAY_CONFIG config;
    KIRQL irql;
    UINT32 code;
    UNREFERENCED_PARAMETER(device);
    if (stack->MajorFunction == IRP_MJ_CREATE || stack->MajorFunction == IRP_MJ_CLOSE || stack->MajorFunction == IRP_MJ_CLEANUP)
        return RpComplete(irp, STATUS_SUCCESS);
    if (stack->MajorFunction != IRP_MJ_DEVICE_CONTROL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return RpComplete(irp, STATUS_INVALID_DEVICE_REQUEST);
    code = stack->Parameters.DeviceIoControl.IoControlCode;
    if (code == RP_IOCTL_CLEAR) {
        if (stack->Parameters.DeviceIoControl.InputBufferLength != 0 ||
            stack->Parameters.DeviceIoControl.OutputBufferLength != 0)
            return RpComplete(irp, STATUS_INVALID_PARAMETER);
        RtlZeroMemory(&config, sizeof(config));
    } else if (code == RP_IOCTL_CONFIGURE) {
        if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(config) ||
            stack->Parameters.DeviceIoControl.OutputBufferLength != 0 || irp->AssociatedIrp.SystemBuffer == NULL)
            return RpComplete(irp, STATUS_INVALID_PARAMETER);
        RtlCopyMemory(&config, irp->AssociatedIrp.SystemBuffer, sizeof(config));
        if (config.version != RP_REDIRECT_ABI || config.size != sizeof(config) || config.reserved != 0 ||
            config.processId == 0 || config.processId > MAXULONG || config.ipv4Port < 1025 || config.ipv6Port < 1025 ||
            RtlCompareMemory(config.generation, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 16)
            return RpComplete(irp, STATUS_INVALID_PARAMETER);
        // Configuration is issued synchronously by the relay itself. Its
        // issuing thread cannot finish exiting before this IRP completes;
        // avoid undocumented process-exit synchronization APIs.
        process = IoGetRequestorProcess(irp);
        if (process == NULL || config.processId != (UINT64)(ULONG_PTR)PsGetProcessId(process))
            return RpComplete(irp, STATUS_ACCESS_DENIED);
        ObReferenceObject(process);
    } else return RpComplete(irp, STATUS_INVALID_DEVICE_REQUEST);
    KeAcquireSpinLock(&RpLock, &irql);
    previous = RpRelayProcess;
    RpRelayProcess = process;
    RpConfig = config;
    RpRelayAlive = process != NULL;
    KeReleaseSpinLock(&RpLock, irql);
    if (previous != NULL) ObDereferenceObject(previous);
    return RpComplete(irp, STATUS_SUCCESS);
}

static NTSTATUS RpDispatch(PDEVICE_OBJECT device, PIRP irp)
{
    NTSTATUS status;
    if (!ExAcquireRundownProtection(&RpRundown)) return RpComplete(irp, STATUS_DEVICE_NOT_READY);
    status = RpDispatchInner(device, irp);
    ExReleaseRundownProtection(&RpRundown);
    return status;
}

static VOID RpUnload(PDRIVER_OBJECT driver)
{
    UINT32 i;
    UNREFERENCED_PARAMETER(driver);
    for (i = 0; i < 2; ++i) {
        if (RpCalloutIds[i] != 0) FwpsCalloutUnregisterById0(RpCalloutIds[i]);
        RpCalloutIds[i] = 0;
    }
    ExWaitForRundownProtectionRelease(&RpRundown);
    if (RpNotifyRegistered) PsSetCreateProcessNotifyRoutineEx(RpProcessNotify, TRUE);
    RpNotifyRegistered = FALSE;
    if (RpRelayProcess != NULL) ObDereferenceObject(RpRelayProcess);
    RpRelayProcess = NULL;
    if (RpRedirectHandle != NULL) FwpsRedirectHandleDestroy0(RpRedirectHandle);
    RpRedirectHandle = NULL;
    IoDeleteSymbolicLink(&RpSymbolicLink);
    if (RpDevice != NULL) IoDeleteDevice(RpDevice);
    RpDevice = NULL;
    // Committed guard and redirect filters are intentionally untouched.
}

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\RuleProxyAleRedirect");
    UNICODE_STRING acl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    NTSTATUS status;
    UINT32 i;
    UNREFERENCED_PARAMETER(registryPath);
    KeInitializeSpinLock(&RpLock);
    ExInitializeRundownProtection(&RpRundown);
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) driver->MajorFunction[i] = RpDispatch;
    driver->DriverUnload = RpUnload;
    status = IoCreateDeviceSecure(driver, 0, &name, RP_DEVICE_TYPE, FILE_DEVICE_SECURE_OPEN,
                                 FALSE, &acl, &RP_DEVICE_CLASS, &RpDevice);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&RpSymbolicLink, &name);
    if (!NT_SUCCESS(status)) goto failed;
    status = FwpsRedirectHandleCreate0(&RP_REDIRECT_V4, 0, &RpRedirectHandle);
    if (!NT_SUCCESS(status)) goto failed;
    status = PsSetCreateProcessNotifyRoutineEx(RpProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) goto failed;
    RpNotifyRegistered = TRUE;
    for (i = 0; i < 2; ++i) {
        FWPS_CALLOUT1 callout;
        RtlZeroMemory(&callout, sizeof(callout));
        callout.calloutKey = i == 0 ? RP_REDIRECT_V4 : RP_REDIRECT_V6;
        callout.classifyFn = RpRedirectClassify;
        callout.notifyFn = RpNotify;
        status = FwpsCalloutRegister1(RpDevice, &callout, &RpCalloutIds[i]);
        if (!NT_SUCCESS(status)) goto failed;
    }
    RpDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
failed:
    RpUnload(driver);
    return status;
}
