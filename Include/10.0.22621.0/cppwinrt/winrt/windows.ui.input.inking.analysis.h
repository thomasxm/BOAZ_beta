// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Inking_Analysis_H
#define WINRT_Windows_UI_Input_Inking_Analysis_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Input.Inking.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.Input.Inking.2.h"
#include "winrt/impl/Windows.UI.Input.Inking.Analysis.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisInkBullet<D>::RecognizedText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkBullet)->get_RecognizedText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisDrawingKind) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisInkDrawing<D>::DrawingKind() const
    {
        winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisDrawingKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing)->get_DrawingKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisInkDrawing<D>::Center() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing)->get_Center(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::Point>) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisInkDrawing<D>::Points() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing)->get_Points(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::Point>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisInkWord<D>::RecognizedText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkWord)->get_RecognizedText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisInkWord<D>::TextAlternates() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkWord)->get_TextAlternates(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisLine<D>::RecognizedText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisLine)->get_RecognizedText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisLine<D>::IndentLevel() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisLine)->get_IndentLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisListItem<D>::RecognizedText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisListItem)->get_RecognizedText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::Id() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->get_Id(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::Kind() const
    {
        winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::BoundingRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->get_BoundingRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::Point>) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::RotatedBoundingRect() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->get_RotatedBoundingRect(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::Point>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::Children() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->get_Children(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::Parent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->get_Parent(&value));
        return winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<uint32_t>) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::GetStrokeIds() const
    {
        void* strokeIds{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->GetStrokeIds(&strokeIds));
        return winrt::Windows::Foundation::Collections::IVectorView<uint32_t>{ strokeIds, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisParagraph<D>::RecognizedText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisParagraph)->get_RecognizedText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisStatus) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisResult<D>::Status() const
    {
        winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisRoot<D>::RecognizedText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisRoot)->get_RecognizedText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisRoot<D>::FindNodes(winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind const& nodeKind) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisRoot)->FindNodes(static_cast<int32_t>(nodeKind), &result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisWritingRegion<D>::RecognizedText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisWritingRegion)->get_RecognizedText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisRoot) consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::AnalysisRoot() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->get_AnalysisRoot(&value));
        return winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisRoot{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::IsAnalyzing() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->get_IsAnalyzing(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::AddDataForStroke(winrt::Windows::UI::Input::Inking::InkStroke const& stroke) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->AddDataForStroke(*(void**)(&stroke)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::AddDataForStrokes(param::iterable<winrt::Windows::UI::Input::Inking::InkStroke> const& strokes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->AddDataForStrokes(*(void**)(&strokes)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::ClearDataForAllStrokes() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->ClearDataForAllStrokes());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::RemoveDataForStroke(uint32_t strokeId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->RemoveDataForStroke(strokeId));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::RemoveDataForStrokes(param::iterable<uint32_t> const& strokeIds) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->RemoveDataForStrokes(*(void**)(&strokeIds)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::ReplaceDataForStroke(winrt::Windows::UI::Input::Inking::InkStroke const& stroke) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->ReplaceDataForStroke(*(void**)(&stroke)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::SetStrokeDataKind(uint32_t strokeId, winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisStrokeKind const& strokeKind) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->SetStrokeDataKind(strokeId, static_cast<int32_t>(strokeKind)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisResult>) consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::AnalyzeAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->AnalyzeAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::Analysis::InkAnalyzer) consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzerFactory<D>::CreateAnalyzer() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzerFactory)->CreateAnalyzer(&result));
        return winrt::Windows::UI::Input::Inking::Analysis::InkAnalyzer{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkBullet> : produce_base<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkBullet>
    {
        int32_t __stdcall get_RecognizedText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing> : produce_base<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing>
    {
        int32_t __stdcall get_DrawingKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisDrawingKind>(this->shim().DrawingKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Center(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Center());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Points(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::Point>>(this->shim().Points());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkWord> : produce_base<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkWord>
    {
        int32_t __stdcall get_RecognizedText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TextAlternates(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().TextAlternates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisLine> : produce_base<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisLine>
    {
        int32_t __stdcall get_RecognizedText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IndentLevel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().IndentLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisListItem> : produce_base<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisListItem>
    {
        int32_t __stdcall get_RecognizedText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode> : produce_base<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>
    {
        int32_t __stdcall get_Id(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BoundingRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().BoundingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RotatedBoundingRect(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::Point>>(this->shim().RotatedBoundingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Children(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>>(this->shim().Children());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Parent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>(this->shim().Parent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStrokeIds(void** strokeIds) noexcept final try
        {
            clear_abi(strokeIds);
            typename D::abi_guard guard(this->shim());
            *strokeIds = detach_from<winrt::Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().GetStrokeIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisParagraph> : produce_base<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisParagraph>
    {
        int32_t __stdcall get_RecognizedText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisResult> : produce_base<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisRoot> : produce_base<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisRoot>
    {
        int32_t __stdcall get_RecognizedText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindNodes(int32_t nodeKind, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>>(this->shim().FindNodes(*reinterpret_cast<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind const*>(&nodeKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisWritingRegion> : produce_base<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisWritingRegion>
    {
        int32_t __stdcall get_RecognizedText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer> : produce_base<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer>
    {
        int32_t __stdcall get_AnalysisRoot(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisRoot>(this->shim().AnalysisRoot());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAnalyzing(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAnalyzing());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDataForStroke(void* stroke) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDataForStroke(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkStroke const*>(&stroke));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDataForStrokes(void* strokes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDataForStrokes(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Input::Inking::InkStroke> const*>(&strokes));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearDataForAllStrokes() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClearDataForAllStrokes();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveDataForStroke(uint32_t strokeId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveDataForStroke(strokeId);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveDataForStrokes(void* strokeIds) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveDataForStrokes(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<uint32_t> const*>(&strokeIds));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReplaceDataForStroke(void* stroke) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReplaceDataForStroke(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkStroke const*>(&stroke));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStrokeDataKind(uint32_t strokeId, int32_t strokeKind) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStrokeDataKind(strokeId, *reinterpret_cast<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisStrokeKind const*>(&strokeKind));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AnalyzeAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisResult>>(this->shim().AnalyzeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzerFactory> : produce_base<D, winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzerFactory>
    {
        int32_t __stdcall CreateAnalyzer(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::Inking::Analysis::InkAnalyzer>(this->shim().CreateAnalyzer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
}
WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking::Analysis
{
    inline InkAnalyzer::InkAnalyzer() :
        InkAnalyzer(impl::call_factory_cast<InkAnalyzer(*)(winrt::Windows::Foundation::IActivationFactory const&), InkAnalyzer>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InkAnalyzer>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkBullet> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkWord> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisLine> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisListItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisParagraph> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisRoot> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisWritingRegion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisInkBullet> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisInkDrawing> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisInkWord> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisLine> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisListItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisParagraph> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisRoot> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisWritingRegion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalyzer> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
