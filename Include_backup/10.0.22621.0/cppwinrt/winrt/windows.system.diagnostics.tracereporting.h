// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Diagnostics_TraceReporting_H
#define WINRT_Windows_System_Diagnostics_TraceReporting_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.Diagnostics.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.Diagnostics.TraceReporting.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::IsScenarioEnabled(winrt::guid const& scenarioId) const
    {
        bool isActive{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->IsScenarioEnabled(impl::bind_in(scenarioId), &isActive));
        return isActive;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::TryEscalateScenario(winrt::guid const& scenarioId, winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEscalationType const& escalationType, param::hstring const& outputDirectory, bool timestampOutputDirectory, bool forceEscalationUpload, param::map_view<hstring, hstring> const& triggers) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->TryEscalateScenario(impl::bind_in(scenarioId), static_cast<int32_t>(escalationType), *(void**)(&outputDirectory), timestampOutputDirectory, forceEscalationUpload, *(void**)(&triggers), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::DownloadLatestSettingsForNamespace(param::hstring const& partner, param::hstring const& feature, bool isScenarioNamespace, bool downloadOverCostedNetwork, bool downloadOverBattery) const
    {
        winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->DownloadLatestSettingsForNamespace(*(void**)(&partner), *(void**)(&feature), isScenarioNamespace, downloadOverCostedNetwork, downloadOverBattery, reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::guid>) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::GetActiveScenarioList() const
    {
        void* scenarioIds{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->GetActiveScenarioList(&scenarioIds));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::guid>{ scenarioIds, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::ForceUpload(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEventBufferLatencies const& latency, bool uploadOverCostedNetwork, bool uploadOverBattery) const
    {
        winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->ForceUpload(static_cast<uint32_t>(latency), uploadOverCostedNetwork, uploadOverBattery, reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotState) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::IsTraceRunning(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType, winrt::guid const& scenarioId, uint64_t traceProfileHash) const
    {
        winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotState slotState{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->IsTraceRunning(static_cast<int32_t>(slotType), impl::bind_in(scenarioId), traceProfileHash, reinterpret_cast<int32_t*>(&slotState)));
        return slotState;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceRuntimeInfo) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::GetActiveTraceRuntime(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType) const
    {
        void* traceRuntimeInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->GetActiveTraceRuntime(static_cast<int32_t>(slotType), &traceRuntimeInfo));
        return winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceRuntimeInfo{ traceRuntimeInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceInfo>) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticActionsStatics<D>::GetKnownTraceList(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType) const
    {
        void* traceInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics)->GetKnownTraceList(static_cast<int32_t>(slotType), &traceInfo));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceInfo>{ traceInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceInfo<D>::ScenarioId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo)->get_ScenarioId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceInfo<D>::ProfileHash() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo)->get_ProfileHash(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceInfo<D>::IsExclusive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo)->get_IsExclusive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceInfo<D>::IsAutoLogger() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo)->get_IsAutoLogger(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceInfo<D>::MaxTraceDurationFileTime() const
    {
        int64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo)->get_MaxTraceDurationFileTime(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTracePriority) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceInfo<D>::Priority() const
    {
        winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTracePriority value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo)->get_Priority(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceRuntimeInfo<D>::RuntimeFileTime() const
    {
        int64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo)->get_RuntimeFileTime(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_System_Diagnostics_TraceReporting_IPlatformDiagnosticTraceRuntimeInfo<D>::EtwRuntimeFileTime() const
    {
        int64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo)->get_EtwRuntimeFileTime(&value));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics> : produce_base<D, winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics>
    {
        int32_t __stdcall IsScenarioEnabled(winrt::guid scenarioId, bool* isActive) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *isActive = detach_from<bool>(this->shim().IsScenarioEnabled(*reinterpret_cast<winrt::guid const*>(&scenarioId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryEscalateScenario(winrt::guid scenarioId, int32_t escalationType, void* outputDirectory, bool timestampOutputDirectory, bool forceEscalationUpload, void* triggers, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryEscalateScenario(*reinterpret_cast<winrt::guid const*>(&scenarioId), *reinterpret_cast<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEscalationType const*>(&escalationType), *reinterpret_cast<hstring const*>(&outputDirectory), timestampOutputDirectory, forceEscalationUpload, *reinterpret_cast<winrt::Windows::Foundation::Collections::IMapView<hstring, hstring> const*>(&triggers)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DownloadLatestSettingsForNamespace(void* partner, void* feature, bool isScenarioNamespace, bool downloadOverCostedNetwork, bool downloadOverBattery, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState>(this->shim().DownloadLatestSettingsForNamespace(*reinterpret_cast<hstring const*>(&partner), *reinterpret_cast<hstring const*>(&feature), isScenarioNamespace, downloadOverCostedNetwork, downloadOverBattery));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetActiveScenarioList(void** scenarioIds) noexcept final try
        {
            clear_abi(scenarioIds);
            typename D::abi_guard guard(this->shim());
            *scenarioIds = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::guid>>(this->shim().GetActiveScenarioList());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ForceUpload(uint32_t latency, bool uploadOverCostedNetwork, bool uploadOverBattery, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActionState>(this->shim().ForceUpload(*reinterpret_cast<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEventBufferLatencies const*>(&latency), uploadOverCostedNetwork, uploadOverBattery));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsTraceRunning(int32_t slotType, winrt::guid scenarioId, uint64_t traceProfileHash, int32_t* slotState) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *slotState = detach_from<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotState>(this->shim().IsTraceRunning(*reinterpret_cast<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const*>(&slotType), *reinterpret_cast<winrt::guid const*>(&scenarioId), traceProfileHash));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetActiveTraceRuntime(int32_t slotType, void** traceRuntimeInfo) noexcept final try
        {
            clear_abi(traceRuntimeInfo);
            typename D::abi_guard guard(this->shim());
            *traceRuntimeInfo = detach_from<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceRuntimeInfo>(this->shim().GetActiveTraceRuntime(*reinterpret_cast<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const*>(&slotType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetKnownTraceList(int32_t slotType, void** traceInfo) noexcept final try
        {
            clear_abi(traceInfo);
            typename D::abi_guard guard(this->shim());
            *traceInfo = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceInfo>>(this->shim().GetKnownTraceList(*reinterpret_cast<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const*>(&slotType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo> : produce_base<D, winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo>
    {
        int32_t __stdcall get_ScenarioId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().ScenarioId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProfileHash(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().ProfileHash());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsExclusive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsExclusive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAutoLogger(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAutoLogger());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxTraceDurationFileTime(int64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int64_t>(this->shim().MaxTraceDurationFileTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Priority(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTracePriority>(this->shim().Priority());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo> : produce_base<D, winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo>
    {
        int32_t __stdcall get_RuntimeFileTime(int64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int64_t>(this->shim().RuntimeFileTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EtwRuntimeFileTime(int64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int64_t>(this->shim().EtwRuntimeFileTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::TraceReporting
{
    constexpr auto operator|(PlatformDiagnosticEventBufferLatencies const left, PlatformDiagnosticEventBufferLatencies const right) noexcept
    {
        return static_cast<PlatformDiagnosticEventBufferLatencies>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(PlatformDiagnosticEventBufferLatencies& left, PlatformDiagnosticEventBufferLatencies const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(PlatformDiagnosticEventBufferLatencies const left, PlatformDiagnosticEventBufferLatencies const right) noexcept
    {
        return static_cast<PlatformDiagnosticEventBufferLatencies>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(PlatformDiagnosticEventBufferLatencies& left, PlatformDiagnosticEventBufferLatencies const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(PlatformDiagnosticEventBufferLatencies const value) noexcept
    {
        return static_cast<PlatformDiagnosticEventBufferLatencies>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(PlatformDiagnosticEventBufferLatencies const left, PlatformDiagnosticEventBufferLatencies const right) noexcept
    {
        return static_cast<PlatformDiagnosticEventBufferLatencies>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(PlatformDiagnosticEventBufferLatencies& left, PlatformDiagnosticEventBufferLatencies const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto PlatformDiagnosticActions::IsScenarioEnabled(winrt::guid const& scenarioId)
    {
        return impl::call_factory<PlatformDiagnosticActions, IPlatformDiagnosticActionsStatics>([&](IPlatformDiagnosticActionsStatics const& f) { return f.IsScenarioEnabled(scenarioId); });
    }
    inline auto PlatformDiagnosticActions::TryEscalateScenario(winrt::guid const& scenarioId, winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEscalationType const& escalationType, param::hstring const& outputDirectory, bool timestampOutputDirectory, bool forceEscalationUpload, param::map_view<hstring, hstring> const& triggers)
    {
        return impl::call_factory<PlatformDiagnosticActions, IPlatformDiagnosticActionsStatics>([&](IPlatformDiagnosticActionsStatics const& f) { return f.TryEscalateScenario(scenarioId, escalationType, outputDirectory, timestampOutputDirectory, forceEscalationUpload, triggers); });
    }
    inline auto PlatformDiagnosticActions::DownloadLatestSettingsForNamespace(param::hstring const& partner, param::hstring const& feature, bool isScenarioNamespace, bool downloadOverCostedNetwork, bool downloadOverBattery)
    {
        return impl::call_factory<PlatformDiagnosticActions, IPlatformDiagnosticActionsStatics>([&](IPlatformDiagnosticActionsStatics const& f) { return f.DownloadLatestSettingsForNamespace(partner, feature, isScenarioNamespace, downloadOverCostedNetwork, downloadOverBattery); });
    }
    inline auto PlatformDiagnosticActions::GetActiveScenarioList()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::guid>(*)(IPlatformDiagnosticActionsStatics const&), PlatformDiagnosticActions, IPlatformDiagnosticActionsStatics>([](IPlatformDiagnosticActionsStatics const& f) { return f.GetActiveScenarioList(); });
    }
    inline auto PlatformDiagnosticActions::ForceUpload(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticEventBufferLatencies const& latency, bool uploadOverCostedNetwork, bool uploadOverBattery)
    {
        return impl::call_factory<PlatformDiagnosticActions, IPlatformDiagnosticActionsStatics>([&](IPlatformDiagnosticActionsStatics const& f) { return f.ForceUpload(latency, uploadOverCostedNetwork, uploadOverBattery); });
    }
    inline auto PlatformDiagnosticActions::IsTraceRunning(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType, winrt::guid const& scenarioId, uint64_t traceProfileHash)
    {
        return impl::call_factory<PlatformDiagnosticActions, IPlatformDiagnosticActionsStatics>([&](IPlatformDiagnosticActionsStatics const& f) { return f.IsTraceRunning(slotType, scenarioId, traceProfileHash); });
    }
    inline auto PlatformDiagnosticActions::GetActiveTraceRuntime(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType)
    {
        return impl::call_factory<PlatformDiagnosticActions, IPlatformDiagnosticActionsStatics>([&](IPlatformDiagnosticActionsStatics const& f) { return f.GetActiveTraceRuntime(slotType); });
    }
    inline auto PlatformDiagnosticActions::GetKnownTraceList(winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceSlotType const& slotType)
    {
        return impl::call_factory<PlatformDiagnosticActions, IPlatformDiagnosticActionsStatics>([&](IPlatformDiagnosticActionsStatics const& f) { return f.GetKnownTraceList(slotType); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticActionsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::TraceReporting::IPlatformDiagnosticTraceRuntimeInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticActions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::TraceReporting::PlatformDiagnosticTraceRuntimeInfo> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
