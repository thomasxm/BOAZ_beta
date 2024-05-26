// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Preview_2_H
#define WINRT_Windows_UI_Input_Preview_2_H
#include "winrt/impl/Windows.UI.WindowManagement.1.h"
#include "winrt/impl/Windows.UI.Input.Preview.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Input::Preview
{
    struct InputActivationListenerPreview
    {
        InputActivationListenerPreview() = delete;
        static auto CreateForApplicationWindow(winrt::Windows::UI::WindowManagement::AppWindow const& window);
    };
}
#endif
