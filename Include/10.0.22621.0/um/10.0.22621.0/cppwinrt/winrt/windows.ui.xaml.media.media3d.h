// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Media_Media3D_H
#define WINRT_Windows_UI_Xaml_Media_Media3D_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Xaml.Media.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Media3D.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::CenterX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_CenterX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::CenterX(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_CenterX(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::CenterY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_CenterY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::CenterY(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_CenterY(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::CenterZ() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_CenterZ(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::CenterZ(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_CenterZ(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::RotationX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_RotationX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::RotationX(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_RotationX(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::RotationY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_RotationY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::RotationY(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_RotationY(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::RotationZ() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_RotationZ(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::RotationZ(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_RotationZ(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::ScaleX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_ScaleX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::ScaleX(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_ScaleX(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::ScaleY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_ScaleY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::ScaleY(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_ScaleY(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::ScaleZ() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_ScaleZ(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::ScaleZ(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_ScaleZ(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::TranslateX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_TranslateX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::TranslateX(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_TranslateX(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::TranslateY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_TranslateY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::TranslateY(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_TranslateY(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::TranslateZ() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->get_TranslateZ(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3D<D>::TranslateZ(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D)->put_TranslateZ(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::CenterXProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_CenterXProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::CenterYProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_CenterYProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::CenterZProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_CenterZProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::RotationXProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_RotationXProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::RotationYProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_RotationYProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::RotationZProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_RotationZProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::ScaleXProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_ScaleXProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::ScaleYProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_ScaleYProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::ScaleZProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_ScaleZProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::TranslateXProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_TranslateXProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::TranslateYProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_TranslateYProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_ICompositeTransform3DStatics<D>::TranslateZProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics)->get_TranslateZProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D) consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>::Identity() const
    {
        winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics)->get_Identity(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D) consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>::Multiply(winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const& matrix1, winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const& matrix2) const
    {
        winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics)->Multiply(impl::bind_in(matrix1), impl::bind_in(matrix2), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D) consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>::FromElements(double m11, double m12, double m13, double m14, double m21, double m22, double m23, double m24, double m31, double m32, double m33, double m34, double offsetX, double offsetY, double offsetZ, double m44) const
    {
        winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics)->FromElements(m11, m12, m13, m14, m21, m22, m23, m24, m31, m32, m33, m34, offsetX, offsetY, offsetZ, m44, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>::GetHasInverse(winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const& target) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics)->GetHasInverse(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>::GetIsIdentity(winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const& target) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics)->GetIsIdentity(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D) consume_Windows_UI_Xaml_Media_Media3D_IMatrix3DHelperStatics<D>::Invert(winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const& target) const
    {
        winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics)->Invert(impl::bind_in(target), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>::Depth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D)->get_Depth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>::Depth(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D)->put_Depth(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>::OffsetX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D)->get_OffsetX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>::OffsetX(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D)->put_OffsetX(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>::OffsetY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D)->get_OffsetY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3D<D>::OffsetY(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D)->put_OffsetY(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3DStatics<D>::DepthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics)->get_DepthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3DStatics<D>::OffsetXProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics)->get_OffsetXProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Media3D_IPerspectiveTransform3DStatics<D>::OffsetYProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics)->get_OffsetYProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Media3D::Transform3D) consume_Windows_UI_Xaml_Media_Media3D_ITransform3DFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Media3D::ITransform3DFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Media3D::Transform3D{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D> : produce_base<D, winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D>
    {
        int32_t __stdcall get_CenterX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CenterX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CenterX(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CenterX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CenterY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CenterY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CenterY(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CenterY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CenterZ(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CenterZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CenterZ(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CenterZ(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RotationX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RotationX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RotationX(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RotationX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RotationY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RotationY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RotationY(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RotationY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RotationZ(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RotationZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RotationZ(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RotationZ(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ScaleX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScaleX(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScaleX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ScaleY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScaleY(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScaleY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleZ(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ScaleZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScaleZ(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScaleZ(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TranslateX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().TranslateX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TranslateX(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TranslateX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TranslateY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().TranslateY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TranslateY(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TranslateY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TranslateZ(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().TranslateZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TranslateZ(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TranslateZ(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics>
    {
        int32_t __stdcall get_CenterXProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CenterXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CenterYProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CenterYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CenterZProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CenterZProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RotationXProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RotationXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RotationYProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RotationYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RotationZProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RotationZProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleXProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ScaleXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleYProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ScaleYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleZProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ScaleZProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TranslateXProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TranslateXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TranslateYProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TranslateYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TranslateZProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TranslateZProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper> : produce_base<D, winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics>
    {
        int32_t __stdcall get_Identity(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D>(this->shim().Identity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Multiply(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D matrix1, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D matrix2, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D>(this->shim().Multiply(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const*>(&matrix1), *reinterpret_cast<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const*>(&matrix2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromElements(double m11, double m12, double m13, double m14, double m21, double m22, double m23, double m24, double m31, double m32, double m33, double m34, double offsetX, double offsetY, double offsetZ, double m44, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D>(this->shim().FromElements(m11, m12, m13, m14, m21, m22, m23, m24, m31, m32, m33, m34, offsetX, offsetY, offsetZ, m44));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetHasInverse(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D target, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetHasInverse(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsIdentity(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D target, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetIsIdentity(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Invert(struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D target, struct struct_Windows_UI_Xaml_Media_Media3D_Matrix3D* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D>(this->shim().Invert(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D> : produce_base<D, winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D>
    {
        int32_t __stdcall get_Depth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Depth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Depth(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Depth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OffsetX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OffsetX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OffsetX(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OffsetX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OffsetY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OffsetY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OffsetY(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OffsetY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics>
    {
        int32_t __stdcall get_DepthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DepthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OffsetXProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OffsetXProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OffsetYProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OffsetYProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Media3D::ITransform3D> : produce_base<D, winrt::Windows::UI::Xaml::Media::Media3D::ITransform3D>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Media3D::ITransform3DFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Media3D::ITransform3DFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Media3D::Transform3D>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Media::Media3D
{
    inline CompositeTransform3D::CompositeTransform3D() :
        CompositeTransform3D(impl::call_factory_cast<CompositeTransform3D(*)(winrt::Windows::Foundation::IActivationFactory const&), CompositeTransform3D>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CompositeTransform3D>(); }))
    {
    }
    inline auto CompositeTransform3D::CenterXProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICompositeTransform3DStatics const&), CompositeTransform3D, ICompositeTransform3DStatics>([](ICompositeTransform3DStatics const& f) { return f.CenterXProperty(); });
    }
    inline auto CompositeTransform3D::CenterYProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICompositeTransform3DStatics const&), CompositeTransform3D, ICompositeTransform3DStatics>([](ICompositeTransform3DStatics const& f) { return f.CenterYProperty(); });
    }
    inline auto CompositeTransform3D::CenterZProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICompositeTransform3DStatics const&), CompositeTransform3D, ICompositeTransform3DStatics>([](ICompositeTransform3DStatics const& f) { return f.CenterZProperty(); });
    }
    inline auto CompositeTransform3D::RotationXProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICompositeTransform3DStatics const&), CompositeTransform3D, ICompositeTransform3DStatics>([](ICompositeTransform3DStatics const& f) { return f.RotationXProperty(); });
    }
    inline auto CompositeTransform3D::RotationYProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICompositeTransform3DStatics const&), CompositeTransform3D, ICompositeTransform3DStatics>([](ICompositeTransform3DStatics const& f) { return f.RotationYProperty(); });
    }
    inline auto CompositeTransform3D::RotationZProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICompositeTransform3DStatics const&), CompositeTransform3D, ICompositeTransform3DStatics>([](ICompositeTransform3DStatics const& f) { return f.RotationZProperty(); });
    }
    inline auto CompositeTransform3D::ScaleXProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICompositeTransform3DStatics const&), CompositeTransform3D, ICompositeTransform3DStatics>([](ICompositeTransform3DStatics const& f) { return f.ScaleXProperty(); });
    }
    inline auto CompositeTransform3D::ScaleYProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICompositeTransform3DStatics const&), CompositeTransform3D, ICompositeTransform3DStatics>([](ICompositeTransform3DStatics const& f) { return f.ScaleYProperty(); });
    }
    inline auto CompositeTransform3D::ScaleZProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICompositeTransform3DStatics const&), CompositeTransform3D, ICompositeTransform3DStatics>([](ICompositeTransform3DStatics const& f) { return f.ScaleZProperty(); });
    }
    inline auto CompositeTransform3D::TranslateXProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICompositeTransform3DStatics const&), CompositeTransform3D, ICompositeTransform3DStatics>([](ICompositeTransform3DStatics const& f) { return f.TranslateXProperty(); });
    }
    inline auto CompositeTransform3D::TranslateYProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICompositeTransform3DStatics const&), CompositeTransform3D, ICompositeTransform3DStatics>([](ICompositeTransform3DStatics const& f) { return f.TranslateYProperty(); });
    }
    inline auto CompositeTransform3D::TranslateZProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICompositeTransform3DStatics const&), CompositeTransform3D, ICompositeTransform3DStatics>([](ICompositeTransform3DStatics const& f) { return f.TranslateZProperty(); });
    }
    inline auto Matrix3DHelper::Identity()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D(*)(IMatrix3DHelperStatics const&), Matrix3DHelper, IMatrix3DHelperStatics>([](IMatrix3DHelperStatics const& f) { return f.Identity(); });
    }
    inline auto Matrix3DHelper::Multiply(winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const& matrix1, winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const& matrix2)
    {
        return impl::call_factory<Matrix3DHelper, IMatrix3DHelperStatics>([&](IMatrix3DHelperStatics const& f) { return f.Multiply(matrix1, matrix2); });
    }
    inline auto Matrix3DHelper::FromElements(double m11, double m12, double m13, double m14, double m21, double m22, double m23, double m24, double m31, double m32, double m33, double m34, double offsetX, double offsetY, double offsetZ, double m44)
    {
        return impl::call_factory<Matrix3DHelper, IMatrix3DHelperStatics>([&](IMatrix3DHelperStatics const& f) { return f.FromElements(m11, m12, m13, m14, m21, m22, m23, m24, m31, m32, m33, m34, offsetX, offsetY, offsetZ, m44); });
    }
    inline auto Matrix3DHelper::GetHasInverse(winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const& target)
    {
        return impl::call_factory<Matrix3DHelper, IMatrix3DHelperStatics>([&](IMatrix3DHelperStatics const& f) { return f.GetHasInverse(target); });
    }
    inline auto Matrix3DHelper::GetIsIdentity(winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const& target)
    {
        return impl::call_factory<Matrix3DHelper, IMatrix3DHelperStatics>([&](IMatrix3DHelperStatics const& f) { return f.GetIsIdentity(target); });
    }
    inline auto Matrix3DHelper::Invert(winrt::Windows::UI::Xaml::Media::Media3D::Matrix3D const& target)
    {
        return impl::call_factory<Matrix3DHelper, IMatrix3DHelperStatics>([&](IMatrix3DHelperStatics const& f) { return f.Invert(target); });
    }
    inline PerspectiveTransform3D::PerspectiveTransform3D() :
        PerspectiveTransform3D(impl::call_factory_cast<PerspectiveTransform3D(*)(winrt::Windows::Foundation::IActivationFactory const&), PerspectiveTransform3D>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PerspectiveTransform3D>(); }))
    {
    }
    inline auto PerspectiveTransform3D::DepthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPerspectiveTransform3DStatics const&), PerspectiveTransform3D, IPerspectiveTransform3DStatics>([](IPerspectiveTransform3DStatics const& f) { return f.DepthProperty(); });
    }
    inline auto PerspectiveTransform3D::OffsetXProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPerspectiveTransform3DStatics const&), PerspectiveTransform3D, IPerspectiveTransform3DStatics>([](IPerspectiveTransform3DStatics const& f) { return f.OffsetXProperty(); });
    }
    inline auto PerspectiveTransform3D::OffsetYProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPerspectiveTransform3DStatics const&), PerspectiveTransform3D, IPerspectiveTransform3DStatics>([](IPerspectiveTransform3DStatics const& f) { return f.OffsetYProperty(); });
    }
    template <typename D, typename... Interfaces>
    struct Transform3DT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Media3D::ITransform3D, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, Transform3D, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = Transform3D;
    protected:
        Transform3DT()
        {
            impl::call_factory<Transform3D, ITransform3DFactory>([&](ITransform3DFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3D> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::ICompositeTransform3DStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::IMatrix3DHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3D> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::IPerspectiveTransform3DStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::ITransform3D> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::ITransform3DFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::CompositeTransform3D> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::Matrix3DHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::PerspectiveTransform3D> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Media3D::Transform3D> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
