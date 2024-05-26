// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Shapes_H
#define WINRT_Windows_UI_Xaml_Shapes_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Xaml.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.2.h"
#include "winrt/impl/Windows.UI.Xaml.Shapes.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Shapes_ILine<D>::X1() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::ILine)->get_X1(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_ILine<D>::X1(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::ILine)->put_X1(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Shapes_ILine<D>::Y1() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::ILine)->get_Y1(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_ILine<D>::Y1(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::ILine)->put_Y1(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Shapes_ILine<D>::X2() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::ILine)->get_X2(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_ILine<D>::X2(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::ILine)->put_X2(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Shapes_ILine<D>::Y2() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::ILine)->get_Y2(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_ILine<D>::Y2(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::ILine)->put_Y2(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_ILineStatics<D>::X1Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::ILineStatics)->get_X1Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_ILineStatics<D>::Y1Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::ILineStatics)->get_Y1Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_ILineStatics<D>::X2Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::ILineStatics)->get_X2Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_ILineStatics<D>::Y2Property() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::ILineStatics)->get_Y2Property(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Geometry) consume_Windows_UI_Xaml_Shapes_IPath<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPath)->get_Data(&value));
        return winrt::Windows::UI::Xaml::Media::Geometry{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IPath<D>::Data(winrt::Windows::UI::Xaml::Media::Geometry const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPath)->put_Data(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Shapes::Path) consume_Windows_UI_Xaml_Shapes_IPathFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPathFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Shapes::Path{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IPathStatics<D>::DataProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPathStatics)->get_DataProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::FillRule) consume_Windows_UI_Xaml_Shapes_IPolygon<D>::FillRule() const
    {
        winrt::Windows::UI::Xaml::Media::FillRule value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPolygon)->get_FillRule(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IPolygon<D>::FillRule(winrt::Windows::UI::Xaml::Media::FillRule const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPolygon)->put_FillRule(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::PointCollection) consume_Windows_UI_Xaml_Shapes_IPolygon<D>::Points() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPolygon)->get_Points(&value));
        return winrt::Windows::UI::Xaml::Media::PointCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IPolygon<D>::Points(winrt::Windows::UI::Xaml::Media::PointCollection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPolygon)->put_Points(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IPolygonStatics<D>::FillRuleProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPolygonStatics)->get_FillRuleProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IPolygonStatics<D>::PointsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPolygonStatics)->get_PointsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::FillRule) consume_Windows_UI_Xaml_Shapes_IPolyline<D>::FillRule() const
    {
        winrt::Windows::UI::Xaml::Media::FillRule value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPolyline)->get_FillRule(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IPolyline<D>::FillRule(winrt::Windows::UI::Xaml::Media::FillRule const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPolyline)->put_FillRule(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::PointCollection) consume_Windows_UI_Xaml_Shapes_IPolyline<D>::Points() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPolyline)->get_Points(&value));
        return winrt::Windows::UI::Xaml::Media::PointCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IPolyline<D>::Points(winrt::Windows::UI::Xaml::Media::PointCollection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPolyline)->put_Points(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IPolylineStatics<D>::FillRuleProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPolylineStatics)->get_FillRuleProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IPolylineStatics<D>::PointsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IPolylineStatics)->get_PointsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Shapes_IRectangle<D>::RadiusX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IRectangle)->get_RadiusX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IRectangle<D>::RadiusX(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IRectangle)->put_RadiusX(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Shapes_IRectangle<D>::RadiusY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IRectangle)->get_RadiusY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IRectangle<D>::RadiusY(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IRectangle)->put_RadiusY(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IRectangleStatics<D>::RadiusXProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IRectangleStatics)->get_RadiusXProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IRectangleStatics<D>::RadiusYProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IRectangleStatics)->get_RadiusYProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Shapes_IShape<D>::Fill() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->get_Fill(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IShape<D>::Fill(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->put_Fill(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) consume_Windows_UI_Xaml_Shapes_IShape<D>::Stroke() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->get_Stroke(&value));
        return winrt::Windows::UI::Xaml::Media::Brush{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IShape<D>::Stroke(winrt::Windows::UI::Xaml::Media::Brush const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->put_Stroke(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeMiterLimit() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->get_StrokeMiterLimit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeMiterLimit(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->put_StrokeMiterLimit(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeThickness() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->get_StrokeThickness(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeThickness(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->put_StrokeThickness(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::PenLineCap) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeStartLineCap() const
    {
        winrt::Windows::UI::Xaml::Media::PenLineCap value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->get_StrokeStartLineCap(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeStartLineCap(winrt::Windows::UI::Xaml::Media::PenLineCap const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->put_StrokeStartLineCap(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::PenLineCap) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeEndLineCap() const
    {
        winrt::Windows::UI::Xaml::Media::PenLineCap value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->get_StrokeEndLineCap(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeEndLineCap(winrt::Windows::UI::Xaml::Media::PenLineCap const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->put_StrokeEndLineCap(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::PenLineJoin) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeLineJoin() const
    {
        winrt::Windows::UI::Xaml::Media::PenLineJoin value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->get_StrokeLineJoin(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeLineJoin(winrt::Windows::UI::Xaml::Media::PenLineJoin const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->put_StrokeLineJoin(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeDashOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->get_StrokeDashOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeDashOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->put_StrokeDashOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::PenLineCap) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeDashCap() const
    {
        winrt::Windows::UI::Xaml::Media::PenLineCap value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->get_StrokeDashCap(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeDashCap(winrt::Windows::UI::Xaml::Media::PenLineCap const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->put_StrokeDashCap(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::DoubleCollection) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeDashArray() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->get_StrokeDashArray(&value));
        return winrt::Windows::UI::Xaml::Media::DoubleCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IShape<D>::StrokeDashArray(winrt::Windows::UI::Xaml::Media::DoubleCollection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->put_StrokeDashArray(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Stretch) consume_Windows_UI_Xaml_Shapes_IShape<D>::Stretch() const
    {
        winrt::Windows::UI::Xaml::Media::Stretch value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->get_Stretch(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Shapes_IShape<D>::Stretch(winrt::Windows::UI::Xaml::Media::Stretch const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->put_Stretch(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Transform) consume_Windows_UI_Xaml_Shapes_IShape<D>::GeometryTransform() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape)->get_GeometryTransform(&value));
        return winrt::Windows::UI::Xaml::Media::Transform{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::CompositionBrush) consume_Windows_UI_Xaml_Shapes_IShape2<D>::GetAlphaMask() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShape2)->GetAlphaMask(&result));
        return winrt::Windows::UI::Composition::CompositionBrush{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Shapes::Shape) consume_Windows_UI_Xaml_Shapes_IShapeFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShapeFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Shapes::Shape{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::FillProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShapeStatics)->get_FillProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeMiterLimitProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeMiterLimitProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeThicknessProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeThicknessProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeStartLineCapProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeStartLineCapProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeEndLineCapProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeEndLineCapProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeLineJoinProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeLineJoinProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeDashOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeDashOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeDashCapProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeDashCapProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StrokeDashArrayProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShapeStatics)->get_StrokeDashArrayProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Shapes_IShapeStatics<D>::StretchProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Shapes::IShapeStatics)->get_StretchProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IEllipse> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IEllipse>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::ILine> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::ILine>
    {
        int32_t __stdcall get_X1(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().X1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_X1(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().X1(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Y1(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Y1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Y1(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Y1(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_X2(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().X2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_X2(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().X2(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Y2(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Y2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Y2(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Y2(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::ILineStatics> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::ILineStatics>
    {
        int32_t __stdcall get_X1Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().X1Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Y1Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().Y1Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_X2Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().X2Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Y2Property(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().Y2Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IPath> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IPath>
    {
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Geometry>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Data(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Data(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Geometry const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IPathFactory> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IPathFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Shapes::Path>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IPathStatics> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IPathStatics>
    {
        int32_t __stdcall get_DataProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DataProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IPolygon> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IPolygon>
    {
        int32_t __stdcall get_FillRule(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::FillRule>(this->shim().FillRule());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FillRule(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FillRule(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::FillRule const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Points(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::PointCollection>(this->shim().Points());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Points(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Points(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::PointCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IPolygonStatics> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IPolygonStatics>
    {
        int32_t __stdcall get_FillRuleProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FillRuleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PointsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IPolyline> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IPolyline>
    {
        int32_t __stdcall get_FillRule(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::FillRule>(this->shim().FillRule());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FillRule(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FillRule(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::FillRule const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Points(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::PointCollection>(this->shim().Points());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Points(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Points(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::PointCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IPolylineStatics> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IPolylineStatics>
    {
        int32_t __stdcall get_FillRuleProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FillRuleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PointsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IRectangle> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IRectangle>
    {
        int32_t __stdcall get_RadiusX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RadiusX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RadiusX(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RadiusX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RadiusY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RadiusY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RadiusY(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RadiusY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IRectangleStatics> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IRectangleStatics>
    {
        int32_t __stdcall get_RadiusXProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RadiusXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RadiusYProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RadiusYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IShape> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IShape>
    {
        int32_t __stdcall get_Fill(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().Fill());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Fill(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Fill(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Stroke(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Brush>(this->shim().Stroke());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Stroke(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stroke(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeMiterLimit(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().StrokeMiterLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StrokeMiterLimit(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeMiterLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeThickness(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().StrokeThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StrokeThickness(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeThickness(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeStartLineCap(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::PenLineCap>(this->shim().StrokeStartLineCap());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StrokeStartLineCap(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeStartLineCap(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::PenLineCap const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeEndLineCap(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::PenLineCap>(this->shim().StrokeEndLineCap());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StrokeEndLineCap(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeEndLineCap(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::PenLineCap const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeLineJoin(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::PenLineJoin>(this->shim().StrokeLineJoin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StrokeLineJoin(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeLineJoin(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::PenLineJoin const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeDashOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().StrokeDashOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StrokeDashOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeDashOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeDashCap(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::PenLineCap>(this->shim().StrokeDashCap());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StrokeDashCap(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeDashCap(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::PenLineCap const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeDashArray(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::DoubleCollection>(this->shim().StrokeDashArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StrokeDashArray(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeDashArray(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::DoubleCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Stretch(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Stretch>(this->shim().Stretch());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Stretch(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stretch(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Stretch const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GeometryTransform(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Transform>(this->shim().GeometryTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IShape2> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IShape2>
    {
        int32_t __stdcall GetAlphaMask(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::CompositionBrush>(this->shim().GetAlphaMask());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IShapeFactory> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IShapeFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Shapes::Shape>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Shapes::IShapeStatics> : produce_base<D, winrt::Windows::UI::Xaml::Shapes::IShapeStatics>
    {
        int32_t __stdcall get_FillProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FillProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeMiterLimitProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeMiterLimitProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeThicknessProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeStartLineCapProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeStartLineCapProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeEndLineCapProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeEndLineCapProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeLineJoinProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeLineJoinProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeDashOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeDashOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeDashCapProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeDashCapProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeDashArrayProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeDashArrayProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StretchProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StretchProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Shapes
{
    inline Ellipse::Ellipse() :
        Ellipse(impl::call_factory_cast<Ellipse(*)(winrt::Windows::Foundation::IActivationFactory const&), Ellipse>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Ellipse>(); }))
    {
    }
    inline Line::Line() :
        Line(impl::call_factory_cast<Line(*)(winrt::Windows::Foundation::IActivationFactory const&), Line>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Line>(); }))
    {
    }
    inline auto Line::X1Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ILineStatics const&), Line, ILineStatics>([](ILineStatics const& f) { return f.X1Property(); });
    }
    inline auto Line::Y1Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ILineStatics const&), Line, ILineStatics>([](ILineStatics const& f) { return f.Y1Property(); });
    }
    inline auto Line::X2Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ILineStatics const&), Line, ILineStatics>([](ILineStatics const& f) { return f.X2Property(); });
    }
    inline auto Line::Y2Property()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ILineStatics const&), Line, ILineStatics>([](ILineStatics const& f) { return f.Y2Property(); });
    }
    inline Path::Path()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<Path, IPathFactory>([&](IPathFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto Path::DataProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPathStatics const&), Path, IPathStatics>([](IPathStatics const& f) { return f.DataProperty(); });
    }
    inline Polygon::Polygon() :
        Polygon(impl::call_factory_cast<Polygon(*)(winrt::Windows::Foundation::IActivationFactory const&), Polygon>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Polygon>(); }))
    {
    }
    inline auto Polygon::FillRuleProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPolygonStatics const&), Polygon, IPolygonStatics>([](IPolygonStatics const& f) { return f.FillRuleProperty(); });
    }
    inline auto Polygon::PointsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPolygonStatics const&), Polygon, IPolygonStatics>([](IPolygonStatics const& f) { return f.PointsProperty(); });
    }
    inline Polyline::Polyline() :
        Polyline(impl::call_factory_cast<Polyline(*)(winrt::Windows::Foundation::IActivationFactory const&), Polyline>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Polyline>(); }))
    {
    }
    inline auto Polyline::FillRuleProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPolylineStatics const&), Polyline, IPolylineStatics>([](IPolylineStatics const& f) { return f.FillRuleProperty(); });
    }
    inline auto Polyline::PointsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPolylineStatics const&), Polyline, IPolylineStatics>([](IPolylineStatics const& f) { return f.PointsProperty(); });
    }
    inline Rectangle::Rectangle() :
        Rectangle(impl::call_factory_cast<Rectangle(*)(winrt::Windows::Foundation::IActivationFactory const&), Rectangle>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Rectangle>(); }))
    {
    }
    inline auto Rectangle::RadiusXProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRectangleStatics const&), Rectangle, IRectangleStatics>([](IRectangleStatics const& f) { return f.RadiusXProperty(); });
    }
    inline auto Rectangle::RadiusYProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRectangleStatics const&), Rectangle, IRectangleStatics>([](IRectangleStatics const& f) { return f.RadiusYProperty(); });
    }
    inline auto Shape::FillProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IShapeStatics const&), Shape, IShapeStatics>([](IShapeStatics const& f) { return f.FillProperty(); });
    }
    inline auto Shape::StrokeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IShapeStatics const&), Shape, IShapeStatics>([](IShapeStatics const& f) { return f.StrokeProperty(); });
    }
    inline auto Shape::StrokeMiterLimitProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IShapeStatics const&), Shape, IShapeStatics>([](IShapeStatics const& f) { return f.StrokeMiterLimitProperty(); });
    }
    inline auto Shape::StrokeThicknessProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IShapeStatics const&), Shape, IShapeStatics>([](IShapeStatics const& f) { return f.StrokeThicknessProperty(); });
    }
    inline auto Shape::StrokeStartLineCapProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IShapeStatics const&), Shape, IShapeStatics>([](IShapeStatics const& f) { return f.StrokeStartLineCapProperty(); });
    }
    inline auto Shape::StrokeEndLineCapProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IShapeStatics const&), Shape, IShapeStatics>([](IShapeStatics const& f) { return f.StrokeEndLineCapProperty(); });
    }
    inline auto Shape::StrokeLineJoinProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IShapeStatics const&), Shape, IShapeStatics>([](IShapeStatics const& f) { return f.StrokeLineJoinProperty(); });
    }
    inline auto Shape::StrokeDashOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IShapeStatics const&), Shape, IShapeStatics>([](IShapeStatics const& f) { return f.StrokeDashOffsetProperty(); });
    }
    inline auto Shape::StrokeDashCapProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IShapeStatics const&), Shape, IShapeStatics>([](IShapeStatics const& f) { return f.StrokeDashCapProperty(); });
    }
    inline auto Shape::StrokeDashArrayProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IShapeStatics const&), Shape, IShapeStatics>([](IShapeStatics const& f) { return f.StrokeDashArrayProperty(); });
    }
    inline auto Shape::StretchProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IShapeStatics const&), Shape, IShapeStatics>([](IShapeStatics const& f) { return f.StretchProperty(); });
    }
    template <typename D, typename... Interfaces>
    struct PathT :
        implements<D, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Shapes::IPath, winrt::Windows::UI::Xaml::Shapes::IShape, winrt::Windows::UI::Xaml::Shapes::IShape2, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, Path, winrt::Windows::UI::Xaml::Shapes::Shape, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = Path;
    protected:
        PathT()
        {
            impl::call_factory<Path, IPathFactory>([&](IPathFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ShapeT :
        implements<D, winrt::Windows::UI::Xaml::IFrameworkElementOverrides, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2, winrt::Windows::UI::Xaml::IUIElementOverrides, winrt::Windows::UI::Xaml::IUIElementOverrides7, winrt::Windows::UI::Xaml::IUIElementOverrides8, winrt::Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Shapes::IShape, winrt::Windows::UI::Xaml::Shapes::IShape2, winrt::Windows::UI::Xaml::IFrameworkElement, winrt::Windows::UI::Xaml::IFrameworkElement2, winrt::Windows::UI::Xaml::IFrameworkElement3, winrt::Windows::UI::Xaml::IFrameworkElement4, winrt::Windows::UI::Xaml::IFrameworkElement6, winrt::Windows::UI::Xaml::IFrameworkElement7, winrt::Windows::UI::Xaml::IFrameworkElementProtected7, winrt::Windows::UI::Xaml::IUIElement, winrt::Windows::UI::Xaml::IUIElement2, winrt::Windows::UI::Xaml::IUIElement3, winrt::Windows::UI::Xaml::IUIElement4, winrt::Windows::UI::Xaml::IUIElement5, winrt::Windows::UI::Xaml::IUIElement7, winrt::Windows::UI::Xaml::IUIElement8, winrt::Windows::UI::Xaml::IUIElement9, winrt::Windows::UI::Xaml::IUIElement10, winrt::Windows::UI::Composition::IAnimationObject, winrt::Windows::UI::Composition::IVisualElement, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, Shape, winrt::Windows::UI::Xaml::FrameworkElement, winrt::Windows::UI::Xaml::UIElement, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::IFrameworkElementOverridesT<D>, winrt::Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, winrt::Windows::UI::Xaml::IUIElementOverridesT<D>, winrt::Windows::UI::Xaml::IUIElementOverrides7T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides8T<D>, winrt::Windows::UI::Xaml::IUIElementOverrides9T<D>
    {
        using composable = Shape;
    protected:
        ShapeT()
        {
            impl::call_factory<Shape, IShapeFactory>([&](IShapeFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IEllipse> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::ILine> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::ILineStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPath> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPathFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPathStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPolygon> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPolygonStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPolyline> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IPolylineStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IRectangle> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IRectangleStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IShape> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IShape2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IShapeFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::IShapeStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Ellipse> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Line> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Path> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Polygon> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Polyline> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Rectangle> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Shapes::Shape> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
