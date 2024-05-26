// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_Deployment_0_H
#define WINRT_Windows_Management_Deployment_0_H
WINRT_EXPORT namespace winrt::Windows::ApplicationModel
{
    struct AppInstallerInfo;
    struct Package;
    enum class PackageContentGroupState : int32_t;
    struct PackageVersion;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct HResult;
    struct IAsyncAction;
    template <typename TResult, typename TProgress> struct __declspec(empty_bases) IAsyncOperationWithProgress;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename K, typename V> struct __declspec(empty_bases) IMap;
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Management::Deployment
{
    enum class AddPackageByAppInstallerOptions : uint32_t
    {
        None = 0,
        InstallAllResources = 0x20,
        ForceTargetAppShutdown = 0x40,
        RequiredContentGroupOnly = 0x100,
        LimitToExistingPackages = 0x200,
    };
    enum class DeploymentOptions : uint32_t
    {
        None = 0,
        ForceApplicationShutdown = 0x1,
        DevelopmentMode = 0x2,
        InstallAllResources = 0x20,
        ForceTargetApplicationShutdown = 0x40,
        RequiredContentGroupOnly = 0x100,
        ForceUpdateFromAnyVersion = 0x40000,
        RetainFilesOnFailure = 0x200000,
        StageInPlace = 0x400000,
    };
    enum class DeploymentProgressState : int32_t
    {
        Queued = 0,
        Processing = 1,
    };
    enum class PackageInstallState : int32_t
    {
        NotInstalled = 0,
        Staged = 1,
        Installed = 2,
        Paused = 6,
    };
    enum class PackageState : int32_t
    {
        Normal = 0,
        LicenseInvalid = 1,
        Modified = 2,
        Tampered = 3,
    };
    enum class PackageStatus : uint32_t
    {
        OK = 0,
        LicenseIssue = 0x1,
        Modified = 0x2,
        Tampered = 0x4,
        Disabled = 0x8,
    };
    enum class PackageStubPreference : int32_t
    {
        Full = 0,
        Stub = 1,
    };
    enum class PackageTypes : uint32_t
    {
        None = 0,
        Main = 0x1,
        Framework = 0x2,
        Resource = 0x4,
        Bundle = 0x8,
        Xap = 0x10,
        Optional = 0x20,
        All = 0xffffffff,
    };
    enum class RemovalOptions : uint32_t
    {
        None = 0,
        PreserveApplicationData = 0x1000,
        PreserveRoamableApplicationData = 0x80,
        RemoveForAllUsers = 0x80000,
    };
    enum class SharedPackageContainerCreationCollisionOptions : int32_t
    {
        FailIfExists = 0,
        MergeWithExisting = 1,
        ReplaceExisting = 2,
    };
    enum class SharedPackageContainerOperationStatus : int32_t
    {
        Success = 0,
        BlockedByPolicy = 1,
        AlreadyExists = 2,
        PackageFamilyExistsInAnotherContainer = 3,
        NotFound = 4,
        UnknownFailure = 5,
    };
    enum class StubPackageOption : int32_t
    {
        Default = 0,
        InstallFull = 1,
        InstallStub = 2,
        UsePreference = 3,
    };
    struct IAddPackageOptions;
    struct IAddPackageOptions2;
    struct IAppInstallerManager;
    struct IAppInstallerManagerStatics;
    struct IAutoUpdateSettingsOptions;
    struct IAutoUpdateSettingsOptionsStatics;
    struct ICreateSharedPackageContainerOptions;
    struct ICreateSharedPackageContainerResult;
    struct IDeleteSharedPackageContainerOptions;
    struct IDeleteSharedPackageContainerResult;
    struct IDeploymentResult;
    struct IDeploymentResult2;
    struct IFindSharedPackageContainerOptions;
    struct IPackageAllUserProvisioningOptions;
    struct IPackageManager;
    struct IPackageManager10;
    struct IPackageManager2;
    struct IPackageManager3;
    struct IPackageManager4;
    struct IPackageManager5;
    struct IPackageManager6;
    struct IPackageManager7;
    struct IPackageManager8;
    struct IPackageManager9;
    struct IPackageManagerDebugSettings;
    struct IPackageUserInformation;
    struct IPackageVolume;
    struct IPackageVolume2;
    struct IRegisterPackageOptions;
    struct IRegisterPackageOptions2;
    struct ISharedPackageContainer;
    struct ISharedPackageContainerManager;
    struct ISharedPackageContainerManagerStatics;
    struct ISharedPackageContainerMember;
    struct ISharedPackageContainerMemberFactory;
    struct IStagePackageOptions;
    struct IStagePackageOptions2;
    struct IUpdateSharedPackageContainerOptions;
    struct IUpdateSharedPackageContainerResult;
    struct AddPackageOptions;
    struct AppInstallerManager;
    struct AutoUpdateSettingsOptions;
    struct CreateSharedPackageContainerOptions;
    struct CreateSharedPackageContainerResult;
    struct DeleteSharedPackageContainerOptions;
    struct DeleteSharedPackageContainerResult;
    struct DeploymentResult;
    struct FindSharedPackageContainerOptions;
    struct PackageAllUserProvisioningOptions;
    struct PackageManager;
    struct PackageManagerDebugSettings;
    struct PackageUserInformation;
    struct PackageVolume;
    struct RegisterPackageOptions;
    struct SharedPackageContainer;
    struct SharedPackageContainerManager;
    struct SharedPackageContainerMember;
    struct StagePackageOptions;
    struct UpdateSharedPackageContainerOptions;
    struct UpdateSharedPackageContainerResult;
    struct DeploymentProgress;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Management::Deployment::IAddPackageOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IAddPackageOptions2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IAppInstallerManager>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IAppInstallerManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IAutoUpdateSettingsOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IAutoUpdateSettingsOptionsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::ICreateSharedPackageContainerOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::ICreateSharedPackageContainerResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IDeleteSharedPackageContainerOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IDeleteSharedPackageContainerResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IDeploymentResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IDeploymentResult2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IFindSharedPackageContainerOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageAllUserProvisioningOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageManager>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageManager10>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageManager2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageManager3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageManager4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageManager5>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageManager6>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageManager7>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageManager8>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageManager9>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageManagerDebugSettings>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageUserInformation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageVolume>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IPackageVolume2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IRegisterPackageOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IRegisterPackageOptions2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::ISharedPackageContainer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::ISharedPackageContainerManager>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::ISharedPackageContainerManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::ISharedPackageContainerMember>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::ISharedPackageContainerMemberFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IStagePackageOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IStagePackageOptions2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IUpdateSharedPackageContainerOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::IUpdateSharedPackageContainerResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Deployment::AddPackageOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::AppInstallerManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::AutoUpdateSettingsOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::CreateSharedPackageContainerOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::CreateSharedPackageContainerResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::DeleteSharedPackageContainerOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::DeleteSharedPackageContainerResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::DeploymentResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::FindSharedPackageContainerOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::PackageAllUserProvisioningOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::PackageManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::PackageManagerDebugSettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::PackageUserInformation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::PackageVolume>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::RegisterPackageOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::SharedPackageContainer>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::SharedPackageContainerManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::SharedPackageContainerMember>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::StagePackageOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::UpdateSharedPackageContainerOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::UpdateSharedPackageContainerResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Deployment::AddPackageByAppInstallerOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Deployment::DeploymentOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Deployment::DeploymentProgressState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Deployment::PackageInstallState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Deployment::PackageState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Deployment::PackageStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Deployment::PackageStubPreference>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Deployment::PackageTypes>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Deployment::RemovalOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Deployment::SharedPackageContainerCreationCollisionOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Deployment::SharedPackageContainerOperationStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Deployment::StubPackageOption>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Deployment::DeploymentProgress>{ using type = struct_category<winrt::Windows::Management::Deployment::DeploymentProgressState, uint32_t>; };
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::AddPackageOptions> = L"Windows.Management.Deployment.AddPackageOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::AppInstallerManager> = L"Windows.Management.Deployment.AppInstallerManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::AutoUpdateSettingsOptions> = L"Windows.Management.Deployment.AutoUpdateSettingsOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::CreateSharedPackageContainerOptions> = L"Windows.Management.Deployment.CreateSharedPackageContainerOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::CreateSharedPackageContainerResult> = L"Windows.Management.Deployment.CreateSharedPackageContainerResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::DeleteSharedPackageContainerOptions> = L"Windows.Management.Deployment.DeleteSharedPackageContainerOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::DeleteSharedPackageContainerResult> = L"Windows.Management.Deployment.DeleteSharedPackageContainerResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::DeploymentResult> = L"Windows.Management.Deployment.DeploymentResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::FindSharedPackageContainerOptions> = L"Windows.Management.Deployment.FindSharedPackageContainerOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::PackageAllUserProvisioningOptions> = L"Windows.Management.Deployment.PackageAllUserProvisioningOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::PackageManager> = L"Windows.Management.Deployment.PackageManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::PackageManagerDebugSettings> = L"Windows.Management.Deployment.PackageManagerDebugSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::PackageUserInformation> = L"Windows.Management.Deployment.PackageUserInformation";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::PackageVolume> = L"Windows.Management.Deployment.PackageVolume";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::RegisterPackageOptions> = L"Windows.Management.Deployment.RegisterPackageOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::SharedPackageContainer> = L"Windows.Management.Deployment.SharedPackageContainer";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::SharedPackageContainerManager> = L"Windows.Management.Deployment.SharedPackageContainerManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::SharedPackageContainerMember> = L"Windows.Management.Deployment.SharedPackageContainerMember";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::StagePackageOptions> = L"Windows.Management.Deployment.StagePackageOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::UpdateSharedPackageContainerOptions> = L"Windows.Management.Deployment.UpdateSharedPackageContainerOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::UpdateSharedPackageContainerResult> = L"Windows.Management.Deployment.UpdateSharedPackageContainerResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::AddPackageByAppInstallerOptions> = L"Windows.Management.Deployment.AddPackageByAppInstallerOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::DeploymentOptions> = L"Windows.Management.Deployment.DeploymentOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::DeploymentProgressState> = L"Windows.Management.Deployment.DeploymentProgressState";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::PackageInstallState> = L"Windows.Management.Deployment.PackageInstallState";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::PackageState> = L"Windows.Management.Deployment.PackageState";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::PackageStatus> = L"Windows.Management.Deployment.PackageStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::PackageStubPreference> = L"Windows.Management.Deployment.PackageStubPreference";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::PackageTypes> = L"Windows.Management.Deployment.PackageTypes";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::RemovalOptions> = L"Windows.Management.Deployment.RemovalOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::SharedPackageContainerCreationCollisionOptions> = L"Windows.Management.Deployment.SharedPackageContainerCreationCollisionOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::SharedPackageContainerOperationStatus> = L"Windows.Management.Deployment.SharedPackageContainerOperationStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::StubPackageOption> = L"Windows.Management.Deployment.StubPackageOption";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::DeploymentProgress> = L"Windows.Management.Deployment.DeploymentProgress";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IAddPackageOptions> = L"Windows.Management.Deployment.IAddPackageOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IAddPackageOptions2> = L"Windows.Management.Deployment.IAddPackageOptions2";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IAppInstallerManager> = L"Windows.Management.Deployment.IAppInstallerManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IAppInstallerManagerStatics> = L"Windows.Management.Deployment.IAppInstallerManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IAutoUpdateSettingsOptions> = L"Windows.Management.Deployment.IAutoUpdateSettingsOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IAutoUpdateSettingsOptionsStatics> = L"Windows.Management.Deployment.IAutoUpdateSettingsOptionsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::ICreateSharedPackageContainerOptions> = L"Windows.Management.Deployment.ICreateSharedPackageContainerOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::ICreateSharedPackageContainerResult> = L"Windows.Management.Deployment.ICreateSharedPackageContainerResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IDeleteSharedPackageContainerOptions> = L"Windows.Management.Deployment.IDeleteSharedPackageContainerOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IDeleteSharedPackageContainerResult> = L"Windows.Management.Deployment.IDeleteSharedPackageContainerResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IDeploymentResult> = L"Windows.Management.Deployment.IDeploymentResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IDeploymentResult2> = L"Windows.Management.Deployment.IDeploymentResult2";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IFindSharedPackageContainerOptions> = L"Windows.Management.Deployment.IFindSharedPackageContainerOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageAllUserProvisioningOptions> = L"Windows.Management.Deployment.IPackageAllUserProvisioningOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageManager> = L"Windows.Management.Deployment.IPackageManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageManager10> = L"Windows.Management.Deployment.IPackageManager10";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageManager2> = L"Windows.Management.Deployment.IPackageManager2";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageManager3> = L"Windows.Management.Deployment.IPackageManager3";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageManager4> = L"Windows.Management.Deployment.IPackageManager4";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageManager5> = L"Windows.Management.Deployment.IPackageManager5";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageManager6> = L"Windows.Management.Deployment.IPackageManager6";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageManager7> = L"Windows.Management.Deployment.IPackageManager7";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageManager8> = L"Windows.Management.Deployment.IPackageManager8";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageManager9> = L"Windows.Management.Deployment.IPackageManager9";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageManagerDebugSettings> = L"Windows.Management.Deployment.IPackageManagerDebugSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageUserInformation> = L"Windows.Management.Deployment.IPackageUserInformation";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageVolume> = L"Windows.Management.Deployment.IPackageVolume";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IPackageVolume2> = L"Windows.Management.Deployment.IPackageVolume2";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IRegisterPackageOptions> = L"Windows.Management.Deployment.IRegisterPackageOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IRegisterPackageOptions2> = L"Windows.Management.Deployment.IRegisterPackageOptions2";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::ISharedPackageContainer> = L"Windows.Management.Deployment.ISharedPackageContainer";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::ISharedPackageContainerManager> = L"Windows.Management.Deployment.ISharedPackageContainerManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::ISharedPackageContainerManagerStatics> = L"Windows.Management.Deployment.ISharedPackageContainerManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::ISharedPackageContainerMember> = L"Windows.Management.Deployment.ISharedPackageContainerMember";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::ISharedPackageContainerMemberFactory> = L"Windows.Management.Deployment.ISharedPackageContainerMemberFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IStagePackageOptions> = L"Windows.Management.Deployment.IStagePackageOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IStagePackageOptions2> = L"Windows.Management.Deployment.IStagePackageOptions2";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IUpdateSharedPackageContainerOptions> = L"Windows.Management.Deployment.IUpdateSharedPackageContainerOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Deployment::IUpdateSharedPackageContainerResult> = L"Windows.Management.Deployment.IUpdateSharedPackageContainerResult";
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IAddPackageOptions>{ 0x05CEE018,0xF68F,0x422B,{ 0x95,0xA4,0x66,0x67,0x9E,0xC7,0x7F,0xC0 } }; // 05CEE018-F68F-422B-95A4-66679EC77FC0
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IAddPackageOptions2>{ 0xEE515828,0xBF33,0x40F7,{ 0x84,0xAF,0x1B,0x6F,0xAD,0x29,0x19,0xD7 } }; // EE515828-BF33-40F7-84AF-1B6FAD2919D7
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IAppInstallerManager>{ 0xE7EE21C3,0x2103,0x53EE,{ 0x9B,0x18,0x68,0xAF,0xEA,0xB0,0x03,0x3D } }; // E7EE21C3-2103-53EE-9B18-68AFEAB0033D
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IAppInstallerManagerStatics>{ 0xC95A6ED5,0xFC59,0x5336,{ 0x9B,0x2E,0x2B,0x07,0xC5,0xE6,0x14,0x34 } }; // C95A6ED5-FC59-5336-9B2E-2B07C5E61434
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IAutoUpdateSettingsOptions>{ 0x67491D87,0x35E1,0x512A,{ 0x89,0x68,0x1A,0xE8,0x8D,0x1B,0xE6,0xD3 } }; // 67491D87-35E1-512A-8968-1AE88D1BE6D3
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IAutoUpdateSettingsOptionsStatics>{ 0x887B337D,0x0C05,0x54D0,{ 0xBD,0x49,0x3B,0xB7,0xA2,0xC0,0x84,0xCB } }; // 887B337D-0C05-54D0-BD49-3BB7A2C084CB
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::ICreateSharedPackageContainerOptions>{ 0xC2AB6ECE,0xF664,0x5C8E,{ 0xA4,0xB3,0x2A,0x33,0x27,0x6D,0x3D,0xDE } }; // C2AB6ECE-F664-5C8E-A4B3-2A33276D3DDE
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::ICreateSharedPackageContainerResult>{ 0xCE8810BF,0x151C,0x5707,{ 0xB9,0x36,0x49,0x7E,0x56,0x4A,0xFC,0x7A } }; // CE8810BF-151C-5707-B936-497E564AFC7A
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IDeleteSharedPackageContainerOptions>{ 0x9D81865F,0x986E,0x5138,{ 0x8B,0x5D,0x38,0x4D,0x8E,0x66,0xED,0x6C } }; // 9D81865F-986E-5138-8B5D-384D8E66ED6C
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IDeleteSharedPackageContainerResult>{ 0x35398884,0x5736,0x517B,{ 0x85,0xBC,0xE5,0x98,0xC8,0x1A,0xB2,0x84 } }; // 35398884-5736-517B-85BC-E598C81AB284
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IDeploymentResult>{ 0x2563B9AE,0xB77D,0x4C1F,{ 0x8A,0x7B,0x20,0xE6,0xAD,0x51,0x5E,0xF3 } }; // 2563B9AE-B77D-4C1F-8A7B-20E6AD515EF3
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IDeploymentResult2>{ 0xFC0E715C,0x5A01,0x4BD7,{ 0xBC,0xF1,0x38,0x1C,0x8C,0x82,0xE0,0x4A } }; // FC0E715C-5A01-4BD7-BCF1-381C8C82E04A
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IFindSharedPackageContainerOptions>{ 0xB40FC8FE,0x8384,0x54CC,{ 0x81,0x7D,0xAE,0x09,0xD3,0xB6,0xA6,0x06 } }; // B40FC8FE-8384-54CC-817D-AE09D3B6A606
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageAllUserProvisioningOptions>{ 0xDA35AA22,0x1DE0,0x5D3E,{ 0x99,0xFF,0xD2,0x4F,0x31,0x18,0xBF,0x5E } }; // DA35AA22-1DE0-5D3E-99FF-D24F3118BF5E
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageManager>{ 0x9A7D4B65,0x5E8F,0x4FC7,{ 0xA2,0xE5,0x7F,0x69,0x25,0xCB,0x8B,0x53 } }; // 9A7D4B65-5E8F-4FC7-A2E5-7F6925CB8B53
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageManager10>{ 0xA7D7D07E,0x2E66,0x4093,{ 0xAE,0xD5,0xE0,0x93,0xED,0x87,0xB3,0xBB } }; // A7D7D07E-2E66-4093-AED5-E093ED87B3BB
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageManager2>{ 0xF7AAD08D,0x0840,0x46F2,{ 0xB5,0xD8,0xCA,0xD4,0x76,0x93,0xA0,0x95 } }; // F7AAD08D-0840-46F2-B5D8-CAD47693A095
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageManager3>{ 0xDAAD9948,0x36F1,0x41A7,{ 0x91,0x88,0xBC,0x26,0x3E,0x0D,0xCB,0x72 } }; // DAAD9948-36F1-41A7-9188-BC263E0DCB72
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageManager4>{ 0x3C719963,0xBAB6,0x46BF,{ 0x8F,0xF7,0xDA,0x47,0x19,0x23,0x0A,0xE6 } }; // 3C719963-BAB6-46BF-8FF7-DA4719230AE6
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageManager5>{ 0x711F3117,0x1AFD,0x4313,{ 0x97,0x8C,0x9B,0xB6,0xE1,0xB8,0x64,0xA7 } }; // 711F3117-1AFD-4313-978C-9BB6E1B864A7
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageManager6>{ 0x0847E909,0x53CD,0x4E4F,{ 0x83,0x2E,0x57,0xD1,0x80,0xF6,0xE4,0x47 } }; // 0847E909-53CD-4E4F-832E-57D180F6E447
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageManager7>{ 0xF28654F4,0x2BA7,0x4B80,{ 0x88,0xD6,0xBE,0x15,0xF9,0xA2,0x3F,0xBA } }; // F28654F4-2BA7-4B80-88D6-BE15F9A23FBA
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageManager8>{ 0xB8575330,0x1298,0x4EE2,{ 0x80,0xEE,0x7F,0x65,0x9C,0x5D,0x27,0x82 } }; // B8575330-1298-4EE2-80EE-7F659C5D2782
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageManager9>{ 0x1AA79035,0xCC71,0x4B2E,{ 0x80,0xA6,0xC7,0x04,0x1D,0x85,0x79,0xA7 } }; // 1AA79035-CC71-4B2E-80A6-C7041D8579A7
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageManagerDebugSettings>{ 0x1A611683,0xA988,0x4FCF,{ 0x8F,0x0F,0xCE,0x17,0x58,0x98,0xE8,0xEB } }; // 1A611683-A988-4FCF-8F0F-CE175898E8EB
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageUserInformation>{ 0xF6383423,0xFA09,0x4CBC,{ 0x90,0x55,0x15,0xCA,0x27,0x5E,0x2E,0x7E } }; // F6383423-FA09-4CBC-9055-15CA275E2E7E
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageVolume>{ 0xCF2672C3,0x1A40,0x4450,{ 0x97,0x39,0x2A,0xCE,0x2E,0x89,0x88,0x53 } }; // CF2672C3-1A40-4450-9739-2ACE2E898853
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IPackageVolume2>{ 0x46ABCF2E,0x9DD4,0x47A2,{ 0xAB,0x8C,0xC6,0x40,0x83,0x49,0xBC,0xD8 } }; // 46ABCF2E-9DD4-47A2-AB8C-C6408349BCD8
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IRegisterPackageOptions>{ 0x677112A7,0x50D4,0x496C,{ 0x84,0x15,0x06,0x02,0xB4,0xC6,0xD3,0xBF } }; // 677112A7-50D4-496C-8415-0602B4C6D3BF
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IRegisterPackageOptions2>{ 0x3DFA9743,0x86FF,0x4A11,{ 0xBC,0x93,0x43,0x4E,0xB6,0xBE,0x3A,0x0B } }; // 3DFA9743-86FF-4A11-BC93-434EB6BE3A0B
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::ISharedPackageContainer>{ 0x177F1AA9,0x151E,0x5EF7,{ 0xB1,0xD9,0x2F,0xBA,0x0B,0x4B,0x0D,0x17 } }; // 177F1AA9-151E-5EF7-B1D9-2FBA0B4B0D17
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::ISharedPackageContainerManager>{ 0xBE353068,0x1EF7,0x5AC8,{ 0xAB,0x3F,0x0B,0x9F,0x61,0x2F,0x02,0x74 } }; // BE353068-1EF7-5AC8-AB3F-0B9F612F0274
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::ISharedPackageContainerManagerStatics>{ 0x2EF56348,0x838A,0x5F55,{ 0xA8,0x9E,0x11,0x98,0xA2,0xC6,0x27,0xE6 } }; // 2EF56348-838A-5F55-A89E-1198A2C627E6
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::ISharedPackageContainerMember>{ 0xFE0D0438,0x43C9,0x5426,{ 0xB8,0x9C,0xF7,0x9B,0xF8,0x5D,0xDF,0xF4 } }; // FE0D0438-43C9-5426-B89C-F79BF85DDFF4
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::ISharedPackageContainerMemberFactory>{ 0x49B0CEEB,0x498F,0x5A62,{ 0xB7,0x38,0xB3,0xCA,0x0D,0x43,0x67,0x04 } }; // 49B0CEEB-498F-5A62-B738-B3CA0D436704
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IStagePackageOptions>{ 0x0B110C9C,0xB95D,0x4C56,{ 0xBD,0x36,0x6D,0x65,0x68,0x00,0xD0,0x6B } }; // 0B110C9C-B95D-4C56-BD36-6D656800D06B
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IStagePackageOptions2>{ 0x990C4CCC,0x6226,0x4192,{ 0xBA,0x92,0x79,0x87,0x5F,0xCE,0x0D,0x9C } }; // 990C4CCC-6226-4192-BA92-79875FCE0D9C
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IUpdateSharedPackageContainerOptions>{ 0x80672E83,0x7194,0x59F9,{ 0xB5,0xB9,0xDA,0xA5,0x37,0x5F,0x13,0x0A } }; // 80672E83-7194-59F9-B5B9-DAA5375F130A
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Deployment::IUpdateSharedPackageContainerResult>{ 0xAA407DF7,0xC72D,0x5458,{ 0xAE,0xA3,0x46,0x45,0xB6,0xA8,0xEE,0x99 } }; // AA407DF7-C72D-5458-AEA3-4645B6A8EE99
    template <> struct default_interface<winrt::Windows::Management::Deployment::AddPackageOptions>{ using type = winrt::Windows::Management::Deployment::IAddPackageOptions; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::AppInstallerManager>{ using type = winrt::Windows::Management::Deployment::IAppInstallerManager; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::AutoUpdateSettingsOptions>{ using type = winrt::Windows::Management::Deployment::IAutoUpdateSettingsOptions; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::CreateSharedPackageContainerOptions>{ using type = winrt::Windows::Management::Deployment::ICreateSharedPackageContainerOptions; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::CreateSharedPackageContainerResult>{ using type = winrt::Windows::Management::Deployment::ICreateSharedPackageContainerResult; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::DeleteSharedPackageContainerOptions>{ using type = winrt::Windows::Management::Deployment::IDeleteSharedPackageContainerOptions; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::DeleteSharedPackageContainerResult>{ using type = winrt::Windows::Management::Deployment::IDeleteSharedPackageContainerResult; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::DeploymentResult>{ using type = winrt::Windows::Management::Deployment::IDeploymentResult; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::FindSharedPackageContainerOptions>{ using type = winrt::Windows::Management::Deployment::IFindSharedPackageContainerOptions; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::PackageAllUserProvisioningOptions>{ using type = winrt::Windows::Management::Deployment::IPackageAllUserProvisioningOptions; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::PackageManager>{ using type = winrt::Windows::Management::Deployment::IPackageManager; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::PackageManagerDebugSettings>{ using type = winrt::Windows::Management::Deployment::IPackageManagerDebugSettings; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::PackageUserInformation>{ using type = winrt::Windows::Management::Deployment::IPackageUserInformation; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::PackageVolume>{ using type = winrt::Windows::Management::Deployment::IPackageVolume; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::RegisterPackageOptions>{ using type = winrt::Windows::Management::Deployment::IRegisterPackageOptions; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::SharedPackageContainer>{ using type = winrt::Windows::Management::Deployment::ISharedPackageContainer; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::SharedPackageContainerManager>{ using type = winrt::Windows::Management::Deployment::ISharedPackageContainerManager; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::SharedPackageContainerMember>{ using type = winrt::Windows::Management::Deployment::ISharedPackageContainerMember; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::StagePackageOptions>{ using type = winrt::Windows::Management::Deployment::IStagePackageOptions; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::UpdateSharedPackageContainerOptions>{ using type = winrt::Windows::Management::Deployment::IUpdateSharedPackageContainerOptions; };
    template <> struct default_interface<winrt::Windows::Management::Deployment::UpdateSharedPackageContainerResult>{ using type = winrt::Windows::Management::Deployment::IUpdateSharedPackageContainerResult; };
    template <> struct abi<winrt::Windows::Management::Deployment::IAddPackageOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DependencyPackageUris(void**) noexcept = 0;
            virtual int32_t __stdcall get_TargetVolume(void**) noexcept = 0;
            virtual int32_t __stdcall put_TargetVolume(void*) noexcept = 0;
            virtual int32_t __stdcall get_OptionalPackageFamilyNames(void**) noexcept = 0;
            virtual int32_t __stdcall get_OptionalPackageUris(void**) noexcept = 0;
            virtual int32_t __stdcall get_RelatedPackageUris(void**) noexcept = 0;
            virtual int32_t __stdcall get_ExternalLocationUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_ExternalLocationUri(void*) noexcept = 0;
            virtual int32_t __stdcall get_StubPackageOption(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_StubPackageOption(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_DeveloperMode(bool*) noexcept = 0;
            virtual int32_t __stdcall put_DeveloperMode(bool) noexcept = 0;
            virtual int32_t __stdcall get_ForceAppShutdown(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ForceAppShutdown(bool) noexcept = 0;
            virtual int32_t __stdcall get_ForceTargetAppShutdown(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ForceTargetAppShutdown(bool) noexcept = 0;
            virtual int32_t __stdcall get_ForceUpdateFromAnyVersion(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ForceUpdateFromAnyVersion(bool) noexcept = 0;
            virtual int32_t __stdcall get_InstallAllResources(bool*) noexcept = 0;
            virtual int32_t __stdcall put_InstallAllResources(bool) noexcept = 0;
            virtual int32_t __stdcall get_RequiredContentGroupOnly(bool*) noexcept = 0;
            virtual int32_t __stdcall put_RequiredContentGroupOnly(bool) noexcept = 0;
            virtual int32_t __stdcall get_RetainFilesOnFailure(bool*) noexcept = 0;
            virtual int32_t __stdcall put_RetainFilesOnFailure(bool) noexcept = 0;
            virtual int32_t __stdcall get_StageInPlace(bool*) noexcept = 0;
            virtual int32_t __stdcall put_StageInPlace(bool) noexcept = 0;
            virtual int32_t __stdcall get_AllowUnsigned(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowUnsigned(bool) noexcept = 0;
            virtual int32_t __stdcall get_DeferRegistrationWhenPackagesAreInUse(bool*) noexcept = 0;
            virtual int32_t __stdcall put_DeferRegistrationWhenPackagesAreInUse(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IAddPackageOptions2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ExpectedDigests(void**) noexcept = 0;
            virtual int32_t __stdcall get_LimitToExistingPackages(bool*) noexcept = 0;
            virtual int32_t __stdcall put_LimitToExistingPackages(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IAppInstallerManager>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetAutoUpdateSettings(void*, void*) noexcept = 0;
            virtual int32_t __stdcall ClearAutoUpdateSettings(void*) noexcept = 0;
            virtual int32_t __stdcall PauseAutoUpdatesUntil(void*, int64_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IAppInstallerManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
            virtual int32_t __stdcall GetForSystem(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IAutoUpdateSettingsOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Version(struct struct_Windows_ApplicationModel_PackageVersion*) noexcept = 0;
            virtual int32_t __stdcall put_Version(struct struct_Windows_ApplicationModel_PackageVersion) noexcept = 0;
            virtual int32_t __stdcall get_AppInstallerUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_AppInstallerUri(void*) noexcept = 0;
            virtual int32_t __stdcall get_OnLaunch(bool*) noexcept = 0;
            virtual int32_t __stdcall put_OnLaunch(bool) noexcept = 0;
            virtual int32_t __stdcall get_HoursBetweenUpdateChecks(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_HoursBetweenUpdateChecks(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ShowPrompt(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ShowPrompt(bool) noexcept = 0;
            virtual int32_t __stdcall get_UpdateBlocksActivation(bool*) noexcept = 0;
            virtual int32_t __stdcall put_UpdateBlocksActivation(bool) noexcept = 0;
            virtual int32_t __stdcall get_AutomaticBackgroundTask(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AutomaticBackgroundTask(bool) noexcept = 0;
            virtual int32_t __stdcall get_ForceUpdateFromAnyVersion(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ForceUpdateFromAnyVersion(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsAutoRepairEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsAutoRepairEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_UpdateUris(void**) noexcept = 0;
            virtual int32_t __stdcall get_RepairUris(void**) noexcept = 0;
            virtual int32_t __stdcall get_DependencyPackageUris(void**) noexcept = 0;
            virtual int32_t __stdcall get_OptionalPackageUris(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IAutoUpdateSettingsOptionsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateFromAppInstallerInfo(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::ICreateSharedPackageContainerOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Members(void**) noexcept = 0;
            virtual int32_t __stdcall get_ForceAppShutdown(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ForceAppShutdown(bool) noexcept = 0;
            virtual int32_t __stdcall get_CreateCollisionOption(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_CreateCollisionOption(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::ICreateSharedPackageContainerResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Container(void**) noexcept = 0;
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IDeleteSharedPackageContainerOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ForceAppShutdown(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ForceAppShutdown(bool) noexcept = 0;
            virtual int32_t __stdcall get_AllUsers(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllUsers(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IDeleteSharedPackageContainerResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IDeploymentResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ErrorText(void**) noexcept = 0;
            virtual int32_t __stdcall get_ActivityId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedErrorCode(winrt::hresult*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IDeploymentResult2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsRegistered(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IFindSharedPackageContainerOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall put_Name(void*) noexcept = 0;
            virtual int32_t __stdcall get_PackageFamilyName(void**) noexcept = 0;
            virtual int32_t __stdcall put_PackageFamilyName(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageAllUserProvisioningOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_OptionalPackageFamilyNames(void**) noexcept = 0;
            virtual int32_t __stdcall get_ProjectionOrderPackageFamilyNames(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageManager>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AddPackageAsync(void*, void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall UpdatePackageAsync(void*, void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall RemovePackageAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall StagePackageAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RegisterPackageAsync(void*, void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackages(void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByUserSecurityId(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByNamePublisher(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByUserSecurityIdNamePublisher(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindUsers(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetPackageState(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall FindPackageByPackageFullName(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CleanupPackageForUserAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByPackageFamilyName(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByUserSecurityIdPackageFamilyName(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackageByUserSecurityIdPackageFullName(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageManager10>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ProvisionPackageForAllUsersWithOptionsAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageManager2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RemovePackageWithOptionsAsync(void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall StagePackageWithOptionsAsync(void*, void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall RegisterPackageByFullNameAsync(void*, void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesWithPackageTypes(uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByUserSecurityIdWithPackageTypes(void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByNamePublisherWithPackageTypes(void*, void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByUserSecurityIdNamePublisherWithPackageTypes(void*, void*, void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByPackageFamilyNameWithPackageTypes(void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByUserSecurityIdPackageFamilyNameWithPackageTypes(void*, void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall StageUserDataAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageManager3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AddPackageVolumeAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall AddPackageToVolumeAsync(void*, void*, uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ClearPackageStatus(void*, uint32_t) noexcept = 0;
            virtual int32_t __stdcall RegisterPackageWithAppDataVolumeAsync(void*, void*, uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackageVolumeByName(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackageVolumes(void**) noexcept = 0;
            virtual int32_t __stdcall GetDefaultPackageVolume(void**) noexcept = 0;
            virtual int32_t __stdcall MovePackageToVolumeAsync(void*, uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RemovePackageVolumeAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetDefaultPackageVolume(void*) noexcept = 0;
            virtual int32_t __stdcall SetPackageStatus(void*, uint32_t) noexcept = 0;
            virtual int32_t __stdcall SetPackageVolumeOfflineAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetPackageVolumeOnlineAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall StagePackageToVolumeAsync(void*, void*, uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall StageUserDataWithOptionsAsync(void*, uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageManager4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetPackageVolumesAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageManager5>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AddPackageToVolumeAndOptionalPackagesAsync(void*, void*, uint32_t, void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall StagePackageToVolumeAndOptionalPackagesAsync(void*, void*, uint32_t, void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RegisterPackageByFamilyNameAndOptionalPackagesAsync(void*, void*, uint32_t, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall get_DebugSettings(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageManager6>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ProvisionPackageForAllUsersAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall AddPackageByAppInstallerFileAsync(void*, uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAddPackageByAppInstallerFileAsync(void*, uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall AddPackageToVolumeAndRelatedSetAsync(void*, void*, uint32_t, void*, void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall StagePackageToVolumeAndRelatedSetAsync(void*, void*, uint32_t, void*, void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAddPackageAsync(void*, void*, uint32_t, void*, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageManager7>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RequestAddPackageAndRelatedSetAsync(void*, void*, uint32_t, void*, void*, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageManager8>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall DeprovisionPackageForAllUsersAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageManager9>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FindProvisionedPackages(void**) noexcept = 0;
            virtual int32_t __stdcall AddPackageByUriAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall StagePackageByUriAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RegisterPackageByUriAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RegisterPackagesByFullNameAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetPackageStubPreference(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall GetPackageStubPreference(void*, int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageManagerDebugSettings>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetContentGroupStateAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall SetContentGroupStateWithPercentageAsync(void*, void*, int32_t, double, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageUserInformation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UserSecurityId(void**) noexcept = 0;
            virtual int32_t __stdcall get_InstallState(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageVolume>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsOffline(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsSystemVolume(bool*) noexcept = 0;
            virtual int32_t __stdcall get_MountPoint(void**) noexcept = 0;
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_PackageStorePath(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportsHardLinks(bool*) noexcept = 0;
            virtual int32_t __stdcall FindPackages(void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByNamePublisher(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByPackageFamilyName(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesWithPackageTypes(uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByNamePublisherWithPackagesTypes(uint32_t, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByPackageFamilyNameWithPackageTypes(uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackageByPackageFullName(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByUserSecurityId(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByUserSecurityIdNamePublisher(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByUserSecurityIdPackageFamilyName(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByUserSecurityIdWithPackageTypes(void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByUserSecurityIdNamePublisherWithPackageTypes(void*, uint32_t, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackagesByUserSecurityIdPackageFamilyNameWithPackagesTypes(void*, uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindPackageByUserSecurityIdPackageFullName(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IPackageVolume2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsFullTrustPackageSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsAppxInstallSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall GetAvailableSpaceAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IRegisterPackageOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DependencyPackageUris(void**) noexcept = 0;
            virtual int32_t __stdcall get_AppDataVolume(void**) noexcept = 0;
            virtual int32_t __stdcall put_AppDataVolume(void*) noexcept = 0;
            virtual int32_t __stdcall get_OptionalPackageFamilyNames(void**) noexcept = 0;
            virtual int32_t __stdcall get_ExternalLocationUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_ExternalLocationUri(void*) noexcept = 0;
            virtual int32_t __stdcall get_DeveloperMode(bool*) noexcept = 0;
            virtual int32_t __stdcall put_DeveloperMode(bool) noexcept = 0;
            virtual int32_t __stdcall get_ForceAppShutdown(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ForceAppShutdown(bool) noexcept = 0;
            virtual int32_t __stdcall get_ForceTargetAppShutdown(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ForceTargetAppShutdown(bool) noexcept = 0;
            virtual int32_t __stdcall get_ForceUpdateFromAnyVersion(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ForceUpdateFromAnyVersion(bool) noexcept = 0;
            virtual int32_t __stdcall get_InstallAllResources(bool*) noexcept = 0;
            virtual int32_t __stdcall put_InstallAllResources(bool) noexcept = 0;
            virtual int32_t __stdcall get_StageInPlace(bool*) noexcept = 0;
            virtual int32_t __stdcall put_StageInPlace(bool) noexcept = 0;
            virtual int32_t __stdcall get_AllowUnsigned(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowUnsigned(bool) noexcept = 0;
            virtual int32_t __stdcall get_DeferRegistrationWhenPackagesAreInUse(bool*) noexcept = 0;
            virtual int32_t __stdcall put_DeferRegistrationWhenPackagesAreInUse(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IRegisterPackageOptions2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ExpectedDigests(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::ISharedPackageContainer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
            virtual int32_t __stdcall GetMembers(void**) noexcept = 0;
            virtual int32_t __stdcall RemovePackageFamily(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ResetData(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::ISharedPackageContainerManager>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateContainer(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall DeleteContainer(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetContainer(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindContainers(void**) noexcept = 0;
            virtual int32_t __stdcall FindContainersWithOptions(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::ISharedPackageContainerManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
            virtual int32_t __stdcall GetForUser(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetForProvisioning(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::ISharedPackageContainerMember>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PackageFamilyName(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::ISharedPackageContainerMemberFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IStagePackageOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DependencyPackageUris(void**) noexcept = 0;
            virtual int32_t __stdcall get_TargetVolume(void**) noexcept = 0;
            virtual int32_t __stdcall put_TargetVolume(void*) noexcept = 0;
            virtual int32_t __stdcall get_OptionalPackageFamilyNames(void**) noexcept = 0;
            virtual int32_t __stdcall get_OptionalPackageUris(void**) noexcept = 0;
            virtual int32_t __stdcall get_RelatedPackageUris(void**) noexcept = 0;
            virtual int32_t __stdcall get_ExternalLocationUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_ExternalLocationUri(void*) noexcept = 0;
            virtual int32_t __stdcall get_StubPackageOption(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_StubPackageOption(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_DeveloperMode(bool*) noexcept = 0;
            virtual int32_t __stdcall put_DeveloperMode(bool) noexcept = 0;
            virtual int32_t __stdcall get_ForceUpdateFromAnyVersion(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ForceUpdateFromAnyVersion(bool) noexcept = 0;
            virtual int32_t __stdcall get_InstallAllResources(bool*) noexcept = 0;
            virtual int32_t __stdcall put_InstallAllResources(bool) noexcept = 0;
            virtual int32_t __stdcall get_RequiredContentGroupOnly(bool*) noexcept = 0;
            virtual int32_t __stdcall put_RequiredContentGroupOnly(bool) noexcept = 0;
            virtual int32_t __stdcall get_StageInPlace(bool*) noexcept = 0;
            virtual int32_t __stdcall put_StageInPlace(bool) noexcept = 0;
            virtual int32_t __stdcall get_AllowUnsigned(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowUnsigned(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IStagePackageOptions2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ExpectedDigests(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IUpdateSharedPackageContainerOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ForceAppShutdown(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ForceAppShutdown(bool) noexcept = 0;
            virtual int32_t __stdcall get_RequirePackagesPresent(bool*) noexcept = 0;
            virtual int32_t __stdcall put_RequirePackagesPresent(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Deployment::IUpdateSharedPackageContainerResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IAddPackageOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) DependencyPackageUris() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::PackageVolume) TargetVolume() const;
        WINRT_IMPL_AUTO(void) TargetVolume(winrt::Windows::Management::Deployment::PackageVolume const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) OptionalPackageFamilyNames() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) OptionalPackageUris() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) RelatedPackageUris() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) ExternalLocationUri() const;
        WINRT_IMPL_AUTO(void) ExternalLocationUri(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::StubPackageOption) StubPackageOption() const;
        WINRT_IMPL_AUTO(void) StubPackageOption(winrt::Windows::Management::Deployment::StubPackageOption const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) DeveloperMode() const;
        WINRT_IMPL_AUTO(void) DeveloperMode(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ForceAppShutdown() const;
        WINRT_IMPL_AUTO(void) ForceAppShutdown(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ForceTargetAppShutdown() const;
        WINRT_IMPL_AUTO(void) ForceTargetAppShutdown(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ForceUpdateFromAnyVersion() const;
        WINRT_IMPL_AUTO(void) ForceUpdateFromAnyVersion(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) InstallAllResources() const;
        WINRT_IMPL_AUTO(void) InstallAllResources(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) RequiredContentGroupOnly() const;
        WINRT_IMPL_AUTO(void) RequiredContentGroupOnly(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) RetainFilesOnFailure() const;
        WINRT_IMPL_AUTO(void) RetainFilesOnFailure(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) StageInPlace() const;
        WINRT_IMPL_AUTO(void) StageInPlace(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowUnsigned() const;
        WINRT_IMPL_AUTO(void) AllowUnsigned(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) DeferRegistrationWhenPackagesAreInUse() const;
        WINRT_IMPL_AUTO(void) DeferRegistrationWhenPackagesAreInUse(bool value) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IAddPackageOptions>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IAddPackageOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IAddPackageOptions2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<winrt::Windows::Foundation::Uri, hstring>) ExpectedDigests() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) LimitToExistingPackages() const;
        WINRT_IMPL_AUTO(void) LimitToExistingPackages(bool value) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IAddPackageOptions2>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IAddPackageOptions2<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IAppInstallerManager
    {
        WINRT_IMPL_AUTO(void) SetAutoUpdateSettings(param::hstring const& packageFamilyName, winrt::Windows::Management::Deployment::AutoUpdateSettingsOptions const& appInstallerInfo) const;
        WINRT_IMPL_AUTO(void) ClearAutoUpdateSettings(param::hstring const& packageFamilyName) const;
        WINRT_IMPL_AUTO(void) PauseAutoUpdatesUntil(param::hstring const& packageFamilyName, winrt::Windows::Foundation::DateTime const& dateTime) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IAppInstallerManager>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IAppInstallerManager<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IAppInstallerManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::AppInstallerManager) GetDefault() const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::AppInstallerManager) GetForSystem() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IAppInstallerManagerStatics>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IAppInstallerManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IAutoUpdateSettingsOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::PackageVersion) Version() const;
        WINRT_IMPL_AUTO(void) Version(winrt::Windows::ApplicationModel::PackageVersion const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) AppInstallerUri() const;
        WINRT_IMPL_AUTO(void) AppInstallerUri(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) OnLaunch() const;
        WINRT_IMPL_AUTO(void) OnLaunch(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) HoursBetweenUpdateChecks() const;
        WINRT_IMPL_AUTO(void) HoursBetweenUpdateChecks(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ShowPrompt() const;
        WINRT_IMPL_AUTO(void) ShowPrompt(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) UpdateBlocksActivation() const;
        WINRT_IMPL_AUTO(void) UpdateBlocksActivation(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AutomaticBackgroundTask() const;
        WINRT_IMPL_AUTO(void) AutomaticBackgroundTask(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ForceUpdateFromAnyVersion() const;
        WINRT_IMPL_AUTO(void) ForceUpdateFromAnyVersion(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAutoRepairEnabled() const;
        WINRT_IMPL_AUTO(void) IsAutoRepairEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) UpdateUris() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) RepairUris() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) DependencyPackageUris() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) OptionalPackageUris() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IAutoUpdateSettingsOptions>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IAutoUpdateSettingsOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IAutoUpdateSettingsOptionsStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::AutoUpdateSettingsOptions) CreateFromAppInstallerInfo(winrt::Windows::ApplicationModel::AppInstallerInfo const& appInstallerInfo) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IAutoUpdateSettingsOptionsStatics>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IAutoUpdateSettingsOptionsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_ICreateSharedPackageContainerOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Management::Deployment::SharedPackageContainerMember>) Members() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ForceAppShutdown() const;
        WINRT_IMPL_AUTO(void) ForceAppShutdown(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::SharedPackageContainerCreationCollisionOptions) CreateCollisionOption() const;
        WINRT_IMPL_AUTO(void) CreateCollisionOption(winrt::Windows::Management::Deployment::SharedPackageContainerCreationCollisionOptions const& value) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::ICreateSharedPackageContainerOptions>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_ICreateSharedPackageContainerOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_ICreateSharedPackageContainerResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::SharedPackageContainer) Container() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::SharedPackageContainerOperationStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::ICreateSharedPackageContainerResult>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_ICreateSharedPackageContainerResult<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IDeleteSharedPackageContainerOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ForceAppShutdown() const;
        WINRT_IMPL_AUTO(void) ForceAppShutdown(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllUsers() const;
        WINRT_IMPL_AUTO(void) AllUsers(bool value) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IDeleteSharedPackageContainerOptions>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IDeleteSharedPackageContainerOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IDeleteSharedPackageContainerResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::SharedPackageContainerOperationStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IDeleteSharedPackageContainerResult>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IDeleteSharedPackageContainerResult<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IDeploymentResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ErrorText() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) ActivityId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedErrorCode() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IDeploymentResult>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IDeploymentResult<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IDeploymentResult2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsRegistered() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IDeploymentResult2>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IDeploymentResult2<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IFindSharedPackageContainerOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        WINRT_IMPL_AUTO(void) Name(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PackageFamilyName() const;
        WINRT_IMPL_AUTO(void) PackageFamilyName(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IFindSharedPackageContainerOptions>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IFindSharedPackageContainerOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageAllUserProvisioningOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) OptionalPackageFamilyNames() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) ProjectionOrderPackageFamilyNames() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageAllUserProvisioningOptions>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageAllUserProvisioningOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageManager
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) AddPackageAsync(winrt::Windows::Foundation::Uri const& packageUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) UpdatePackageAsync(winrt::Windows::Foundation::Uri const& packageUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) RemovePackageAsync(param::hstring const& packageFullName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) StagePackageAsync(winrt::Windows::Foundation::Uri const& packageUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) RegisterPackageAsync(winrt::Windows::Foundation::Uri const& manifestUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package>) FindPackages() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package>) FindPackagesForUser(param::hstring const& userSecurityId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package>) FindPackages(param::hstring const& packageName, param::hstring const& packagePublisher) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package>) FindPackagesForUser(param::hstring const& userSecurityId, param::hstring const& packageName, param::hstring const& packagePublisher) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Management::Deployment::PackageUserInformation>) FindUsers(param::hstring const& packageFullName) const;
        WINRT_IMPL_AUTO(void) SetPackageState(param::hstring const& packageFullName, winrt::Windows::Management::Deployment::PackageState const& packageState) const;
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Package) FindPackage(param::hstring const& packageFullName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) CleanupPackageForUserAsync(param::hstring const& packageName, param::hstring const& userSecurityId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package>) FindPackages(param::hstring const& packageFamilyName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package>) FindPackagesForUser(param::hstring const& userSecurityId, param::hstring const& packageFamilyName) const;
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Package) FindPackageForUser(param::hstring const& userSecurityId, param::hstring const& packageFullName) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageManager>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageManager10
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) ProvisionPackageForAllUsersAsync(param::hstring const& mainPackageFamilyName, winrt::Windows::Management::Deployment::PackageAllUserProvisioningOptions const& options) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageManager10>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager10<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageManager2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) RemovePackageAsync(param::hstring const& packageFullName, winrt::Windows::Management::Deployment::RemovalOptions const& removalOptions) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) StagePackageAsync(winrt::Windows::Foundation::Uri const& packageUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) RegisterPackageByFullNameAsync(param::hstring const& mainPackageFullName, param::async_iterable<hstring> const& dependencyPackageFullNames, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package>) FindPackagesWithPackageTypes(winrt::Windows::Management::Deployment::PackageTypes const& packageTypes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package>) FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, winrt::Windows::Management::Deployment::PackageTypes const& packageTypes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package>) FindPackagesWithPackageTypes(param::hstring const& packageName, param::hstring const& packagePublisher, winrt::Windows::Management::Deployment::PackageTypes const& packageTypes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package>) FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, param::hstring const& packageName, param::hstring const& packagePublisher, winrt::Windows::Management::Deployment::PackageTypes const& packageTypes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package>) FindPackagesWithPackageTypes(param::hstring const& packageFamilyName, winrt::Windows::Management::Deployment::PackageTypes const& packageTypes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package>) FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, param::hstring const& packageFamilyName, winrt::Windows::Management::Deployment::PackageTypes const& packageTypes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) StageUserDataAsync(param::hstring const& packageFullName) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageManager2>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager2<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageManager3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Management::Deployment::PackageVolume>) AddPackageVolumeAsync(param::hstring const& packageStorePath) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) AddPackageAsync(winrt::Windows::Foundation::Uri const& packageUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume) const;
        WINRT_IMPL_AUTO(void) ClearPackageStatus(param::hstring const& packageFullName, winrt::Windows::Management::Deployment::PackageStatus const& status) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) RegisterPackageAsync(winrt::Windows::Foundation::Uri const& manifestUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, winrt::Windows::Management::Deployment::PackageVolume const& appDataVolume) const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::PackageVolume) FindPackageVolume(param::hstring const& volumeName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Management::Deployment::PackageVolume>) FindPackageVolumes() const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::PackageVolume) GetDefaultPackageVolume() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) MovePackageToVolumeAsync(param::hstring const& packageFullName, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) RemovePackageVolumeAsync(winrt::Windows::Management::Deployment::PackageVolume const& volume) const;
        WINRT_IMPL_AUTO(void) SetDefaultPackageVolume(winrt::Windows::Management::Deployment::PackageVolume const& volume) const;
        WINRT_IMPL_AUTO(void) SetPackageStatus(param::hstring const& packageFullName, winrt::Windows::Management::Deployment::PackageStatus const& status) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) SetPackageVolumeOfflineAsync(winrt::Windows::Management::Deployment::PackageVolume const& packageVolume) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) SetPackageVolumeOnlineAsync(winrt::Windows::Management::Deployment::PackageVolume const& packageVolume) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) StagePackageAsync(winrt::Windows::Foundation::Uri const& packageUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) StageUserDataAsync(param::hstring const& packageFullName, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageManager3>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager3<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageManager4
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Management::Deployment::PackageVolume>>) GetPackageVolumesAsync() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageManager4>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager4<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageManager5
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) AddPackageAsync(winrt::Windows::Foundation::Uri const& packageUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<winrt::Windows::Foundation::Uri> const& externalPackageUris) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) StagePackageAsync(winrt::Windows::Foundation::Uri const& packageUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<winrt::Windows::Foundation::Uri> const& externalPackageUris) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) RegisterPackageByFamilyNameAsync(param::hstring const& mainPackageFamilyName, param::async_iterable<hstring> const& dependencyPackageFamilyNames, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, winrt::Windows::Management::Deployment::PackageVolume const& appDataVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::PackageManagerDebugSettings) DebugSettings() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageManager5>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager5<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageManager6
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) ProvisionPackageForAllUsersAsync(param::hstring const& packageFamilyName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) AddPackageByAppInstallerFileAsync(winrt::Windows::Foundation::Uri const& appInstallerFileUri, winrt::Windows::Management::Deployment::AddPackageByAppInstallerOptions const& options, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) RequestAddPackageByAppInstallerFileAsync(winrt::Windows::Foundation::Uri const& appInstallerFileUri, winrt::Windows::Management::Deployment::AddPackageByAppInstallerOptions const& options, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) AddPackageAsync(winrt::Windows::Foundation::Uri const& packageUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& options, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<winrt::Windows::Foundation::Uri> const& packageUrisToInstall, param::async_iterable<winrt::Windows::Foundation::Uri> const& relatedPackageUris) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) StagePackageAsync(winrt::Windows::Foundation::Uri const& packageUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& options, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<winrt::Windows::Foundation::Uri> const& packageUrisToInstall, param::async_iterable<winrt::Windows::Foundation::Uri> const& relatedPackageUris) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) RequestAddPackageAsync(winrt::Windows::Foundation::Uri const& packageUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<winrt::Windows::Foundation::Uri> const& relatedPackageUris) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageManager6>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager6<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageManager7
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) RequestAddPackageAsync(winrt::Windows::Foundation::Uri const& packageUri, param::async_iterable<winrt::Windows::Foundation::Uri> const& dependencyPackageUris, winrt::Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, winrt::Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<winrt::Windows::Foundation::Uri> const& relatedPackageUris, param::async_iterable<winrt::Windows::Foundation::Uri> const& packageUrisToInstall) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageManager7>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager7<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageManager8
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) DeprovisionPackageForAllUsersAsync(param::hstring const& packageFamilyName) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageManager8>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager8<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageManager9
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindProvisionedPackages() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) AddPackageByUriAsync(winrt::Windows::Foundation::Uri const& packageUri, winrt::Windows::Management::Deployment::AddPackageOptions const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) StagePackageByUriAsync(winrt::Windows::Foundation::Uri const& packageUri, winrt::Windows::Management::Deployment::StagePackageOptions const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) RegisterPackageByUriAsync(winrt::Windows::Foundation::Uri const& manifestUri, winrt::Windows::Management::Deployment::RegisterPackageOptions const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Management::Deployment::DeploymentResult, winrt::Windows::Management::Deployment::DeploymentProgress>) RegisterPackagesByFullNameAsync(param::async_iterable<hstring> const& packageFullNames, winrt::Windows::Management::Deployment::RegisterPackageOptions const& options) const;
        WINRT_IMPL_AUTO(void) SetPackageStubPreference(param::hstring const& packageFamilyName, winrt::Windows::Management::Deployment::PackageStubPreference const& useStub) const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::PackageStubPreference) GetPackageStubPreference(param::hstring const& packageFamilyName) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageManager9>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager9<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageManagerDebugSettings
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetContentGroupStateAsync(winrt::Windows::ApplicationModel::Package const& package, param::hstring const& contentGroupName, winrt::Windows::ApplicationModel::PackageContentGroupState const& state) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetContentGroupStateAsync(winrt::Windows::ApplicationModel::Package const& package, param::hstring const& contentGroupName, winrt::Windows::ApplicationModel::PackageContentGroupState const& state, double completionPercentage) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageManagerDebugSettings>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageManagerDebugSettings<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageUserInformation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UserSecurityId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::PackageInstallState) InstallState() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageUserInformation>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageUserInformation<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageVolume
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsOffline() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSystemVolume() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) MountPoint() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PackageStorePath() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) SupportsHardLinks() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackages() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackages(param::hstring const& packageName, param::hstring const& packagePublisher) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackages(param::hstring const& packageFamilyName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackagesWithPackageTypes(winrt::Windows::Management::Deployment::PackageTypes const& packageTypes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackagesWithPackageTypes(winrt::Windows::Management::Deployment::PackageTypes const& packageTypes, param::hstring const& packageName, param::hstring const& packagePublisher) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackagesWithPackageTypes(winrt::Windows::Management::Deployment::PackageTypes const& packageTypes, param::hstring const& packageFamilyName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackage(param::hstring const& packageFullName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackagesForUser(param::hstring const& userSecurityId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackagesForUser(param::hstring const& userSecurityId, param::hstring const& packageName, param::hstring const& packagePublisher) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackagesForUser(param::hstring const& userSecurityId, param::hstring const& packageFamilyName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, winrt::Windows::Management::Deployment::PackageTypes const& packageTypes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, winrt::Windows::Management::Deployment::PackageTypes const& packageTypes, param::hstring const& packageName, param::hstring const& packagePublisher) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, winrt::Windows::Management::Deployment::PackageTypes const& packageTypes, param::hstring const& packageFamilyName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Package>) FindPackageForUser(param::hstring const& userSecurityId, param::hstring const& packageFullName) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageVolume>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageVolume<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IPackageVolume2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsFullTrustPackageSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAppxInstallSupported() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<uint64_t>) GetAvailableSpaceAsync() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IPackageVolume2>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IPackageVolume2<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IRegisterPackageOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) DependencyPackageUris() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::PackageVolume) AppDataVolume() const;
        WINRT_IMPL_AUTO(void) AppDataVolume(winrt::Windows::Management::Deployment::PackageVolume const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) OptionalPackageFamilyNames() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) ExternalLocationUri() const;
        WINRT_IMPL_AUTO(void) ExternalLocationUri(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) DeveloperMode() const;
        WINRT_IMPL_AUTO(void) DeveloperMode(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ForceAppShutdown() const;
        WINRT_IMPL_AUTO(void) ForceAppShutdown(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ForceTargetAppShutdown() const;
        WINRT_IMPL_AUTO(void) ForceTargetAppShutdown(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ForceUpdateFromAnyVersion() const;
        WINRT_IMPL_AUTO(void) ForceUpdateFromAnyVersion(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) InstallAllResources() const;
        WINRT_IMPL_AUTO(void) InstallAllResources(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) StageInPlace() const;
        WINRT_IMPL_AUTO(void) StageInPlace(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowUnsigned() const;
        WINRT_IMPL_AUTO(void) AllowUnsigned(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) DeferRegistrationWhenPackagesAreInUse() const;
        WINRT_IMPL_AUTO(void) DeferRegistrationWhenPackagesAreInUse(bool value) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IRegisterPackageOptions>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IRegisterPackageOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IRegisterPackageOptions2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<winrt::Windows::Foundation::Uri, hstring>) ExpectedDigests() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IRegisterPackageOptions2>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IRegisterPackageOptions2<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_ISharedPackageContainer
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Management::Deployment::SharedPackageContainerMember>) GetMembers() const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::UpdateSharedPackageContainerResult) RemovePackageFamily(param::hstring const& packageFamilyName, winrt::Windows::Management::Deployment::UpdateSharedPackageContainerOptions const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::UpdateSharedPackageContainerResult) ResetData() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::ISharedPackageContainer>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_ISharedPackageContainer<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_ISharedPackageContainerManager
    {
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::CreateSharedPackageContainerResult) CreateContainer(param::hstring const& name, winrt::Windows::Management::Deployment::CreateSharedPackageContainerOptions const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::DeleteSharedPackageContainerResult) DeleteContainer(param::hstring const& id, winrt::Windows::Management::Deployment::DeleteSharedPackageContainerOptions const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::SharedPackageContainer) GetContainer(param::hstring const& id) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Management::Deployment::SharedPackageContainer>) FindContainers() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Management::Deployment::SharedPackageContainer>) FindContainers(winrt::Windows::Management::Deployment::FindSharedPackageContainerOptions const& options) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::ISharedPackageContainerManager>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_ISharedPackageContainerManager<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_ISharedPackageContainerManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::SharedPackageContainerManager) GetDefault() const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::SharedPackageContainerManager) GetForUser(param::hstring const& userSid) const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::SharedPackageContainerManager) GetForProvisioning() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::ISharedPackageContainerManagerStatics>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_ISharedPackageContainerManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_ISharedPackageContainerMember
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PackageFamilyName() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::ISharedPackageContainerMember>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_ISharedPackageContainerMember<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_ISharedPackageContainerMemberFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::SharedPackageContainerMember) CreateInstance(param::hstring const& packageFamilyName) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::ISharedPackageContainerMemberFactory>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_ISharedPackageContainerMemberFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IStagePackageOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) DependencyPackageUris() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::PackageVolume) TargetVolume() const;
        WINRT_IMPL_AUTO(void) TargetVolume(winrt::Windows::Management::Deployment::PackageVolume const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) OptionalPackageFamilyNames() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) OptionalPackageUris() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) RelatedPackageUris() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) ExternalLocationUri() const;
        WINRT_IMPL_AUTO(void) ExternalLocationUri(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::StubPackageOption) StubPackageOption() const;
        WINRT_IMPL_AUTO(void) StubPackageOption(winrt::Windows::Management::Deployment::StubPackageOption const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) DeveloperMode() const;
        WINRT_IMPL_AUTO(void) DeveloperMode(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ForceUpdateFromAnyVersion() const;
        WINRT_IMPL_AUTO(void) ForceUpdateFromAnyVersion(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) InstallAllResources() const;
        WINRT_IMPL_AUTO(void) InstallAllResources(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) RequiredContentGroupOnly() const;
        WINRT_IMPL_AUTO(void) RequiredContentGroupOnly(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) StageInPlace() const;
        WINRT_IMPL_AUTO(void) StageInPlace(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowUnsigned() const;
        WINRT_IMPL_AUTO(void) AllowUnsigned(bool value) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IStagePackageOptions>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IStagePackageOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IStagePackageOptions2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<winrt::Windows::Foundation::Uri, hstring>) ExpectedDigests() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IStagePackageOptions2>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IStagePackageOptions2<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IUpdateSharedPackageContainerOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ForceAppShutdown() const;
        WINRT_IMPL_AUTO(void) ForceAppShutdown(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) RequirePackagesPresent() const;
        WINRT_IMPL_AUTO(void) RequirePackagesPresent(bool value) const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IUpdateSharedPackageContainerOptions>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IUpdateSharedPackageContainerOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Deployment_IUpdateSharedPackageContainerResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Deployment::SharedPackageContainerOperationStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
    };
    template <> struct consume<winrt::Windows::Management::Deployment::IUpdateSharedPackageContainerResult>
    {
        template <typename D> using type = consume_Windows_Management_Deployment_IUpdateSharedPackageContainerResult<D>;
    };
    struct struct_Windows_Management_Deployment_DeploymentProgress
    {
        int32_t state;
        uint32_t percentage;
    };
    template <> struct abi<Windows::Management::Deployment::DeploymentProgress>
    {
        using type = struct_Windows_Management_Deployment_DeploymentProgress;
    };
}
#endif
