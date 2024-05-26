// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Sensors_0_H
#define WINRT_Windows_Devices_Sensors_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename T> struct __declspec(empty_bases) EventHandler;
    struct EventRegistrationToken;
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    struct IClosable;
    template <typename T> struct __declspec(empty_bases) IReference;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename K, typename V> struct __declspec(empty_bases) IMapView;
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Display
{
    enum class DisplayOrientations : uint32_t;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Sensors
{
    enum class AccelerometerReadingType : int32_t
    {
        Standard = 0,
        Linear = 1,
        Gravity = 2,
    };
    enum class ActivitySensorReadingConfidence : int32_t
    {
        High = 0,
        Low = 1,
    };
    enum class ActivityType : int32_t
    {
        Unknown = 0,
        Idle = 1,
        Stationary = 2,
        Fidgeting = 3,
        Walking = 4,
        Running = 5,
        InVehicle = 6,
        Biking = 7,
    };
    enum class HumanEngagement : int32_t
    {
        Unknown = 0,
        Engaged = 1,
        Unengaged = 2,
    };
    enum class HumanPresence : int32_t
    {
        Unknown = 0,
        Present = 1,
        NotPresent = 2,
    };
    enum class MagnetometerAccuracy : int32_t
    {
        Unknown = 0,
        Unreliable = 1,
        Approximate = 2,
        High = 3,
    };
    enum class PedometerStepKind : int32_t
    {
        Unknown = 0,
        Walking = 1,
        Running = 2,
    };
    enum class SensorOptimizationGoal : int32_t
    {
        Precision = 0,
        PowerEfficiency = 1,
    };
    enum class SensorReadingType : int32_t
    {
        Absolute = 0,
        Relative = 1,
    };
    enum class SensorType : int32_t
    {
        Accelerometer = 0,
        ActivitySensor = 1,
        Barometer = 2,
        Compass = 3,
        CustomSensor = 4,
        Gyroscope = 5,
        ProximitySensor = 6,
        Inclinometer = 7,
        LightSensor = 8,
        OrientationSensor = 9,
        Pedometer = 10,
        RelativeInclinometer = 11,
        RelativeOrientationSensor = 12,
        SimpleOrientationSensor = 13,
    };
    enum class SimpleOrientation : int32_t
    {
        NotRotated = 0,
        Rotated90DegreesCounterclockwise = 1,
        Rotated180DegreesCounterclockwise = 2,
        Rotated270DegreesCounterclockwise = 3,
        Faceup = 4,
        Facedown = 5,
    };
    struct IAccelerometer;
    struct IAccelerometer2;
    struct IAccelerometer3;
    struct IAccelerometer4;
    struct IAccelerometer5;
    struct IAccelerometerDataThreshold;
    struct IAccelerometerDeviceId;
    struct IAccelerometerReading;
    struct IAccelerometerReading2;
    struct IAccelerometerReadingChangedEventArgs;
    struct IAccelerometerShakenEventArgs;
    struct IAccelerometerStatics;
    struct IAccelerometerStatics2;
    struct IAccelerometerStatics3;
    struct IActivitySensor;
    struct IActivitySensorReading;
    struct IActivitySensorReadingChangeReport;
    struct IActivitySensorReadingChangedEventArgs;
    struct IActivitySensorStatics;
    struct IActivitySensorTriggerDetails;
    struct IAdaptiveDimmingOptions;
    struct IAltimeter;
    struct IAltimeter2;
    struct IAltimeterReading;
    struct IAltimeterReading2;
    struct IAltimeterReadingChangedEventArgs;
    struct IAltimeterStatics;
    struct IBarometer;
    struct IBarometer2;
    struct IBarometer3;
    struct IBarometerDataThreshold;
    struct IBarometerReading;
    struct IBarometerReading2;
    struct IBarometerReadingChangedEventArgs;
    struct IBarometerStatics;
    struct IBarometerStatics2;
    struct ICompass;
    struct ICompass2;
    struct ICompass3;
    struct ICompass4;
    struct ICompassDataThreshold;
    struct ICompassDeviceId;
    struct ICompassReading;
    struct ICompassReading2;
    struct ICompassReadingChangedEventArgs;
    struct ICompassReadingHeadingAccuracy;
    struct ICompassStatics;
    struct ICompassStatics2;
    struct IGyrometer;
    struct IGyrometer2;
    struct IGyrometer3;
    struct IGyrometer4;
    struct IGyrometerDataThreshold;
    struct IGyrometerDeviceId;
    struct IGyrometerReading;
    struct IGyrometerReading2;
    struct IGyrometerReadingChangedEventArgs;
    struct IGyrometerStatics;
    struct IGyrometerStatics2;
    struct IHingeAngleReading;
    struct IHingeAngleSensor;
    struct IHingeAngleSensorReadingChangedEventArgs;
    struct IHingeAngleSensorStatics;
    struct IHumanPresenceFeatures;
    struct IHumanPresenceFeatures2;
    struct IHumanPresenceSensor;
    struct IHumanPresenceSensor2;
    struct IHumanPresenceSensorExtension;
    struct IHumanPresenceSensorReading;
    struct IHumanPresenceSensorReading2;
    struct IHumanPresenceSensorReadingChangedEventArgs;
    struct IHumanPresenceSensorReadingUpdate;
    struct IHumanPresenceSensorStatics;
    struct IHumanPresenceSensorStatics2;
    struct IHumanPresenceSettings;
    struct IHumanPresenceSettings2;
    struct IHumanPresenceSettingsStatics;
    struct IInclinometer;
    struct IInclinometer2;
    struct IInclinometer3;
    struct IInclinometer4;
    struct IInclinometerDataThreshold;
    struct IInclinometerDeviceId;
    struct IInclinometerReading;
    struct IInclinometerReading2;
    struct IInclinometerReadingChangedEventArgs;
    struct IInclinometerReadingYawAccuracy;
    struct IInclinometerStatics;
    struct IInclinometerStatics2;
    struct IInclinometerStatics3;
    struct IInclinometerStatics4;
    struct ILightSensor;
    struct ILightSensor2;
    struct ILightSensor3;
    struct ILightSensorDataThreshold;
    struct ILightSensorDeviceId;
    struct ILightSensorReading;
    struct ILightSensorReading2;
    struct ILightSensorReadingChangedEventArgs;
    struct ILightSensorStatics;
    struct ILightSensorStatics2;
    struct ILockOnLeaveOptions;
    struct IMagnetometer;
    struct IMagnetometer2;
    struct IMagnetometer3;
    struct IMagnetometer4;
    struct IMagnetometerDataThreshold;
    struct IMagnetometerDeviceId;
    struct IMagnetometerReading;
    struct IMagnetometerReading2;
    struct IMagnetometerReadingChangedEventArgs;
    struct IMagnetometerStatics;
    struct IMagnetometerStatics2;
    struct IOrientationSensor;
    struct IOrientationSensor2;
    struct IOrientationSensor3;
    struct IOrientationSensorDeviceId;
    struct IOrientationSensorReading;
    struct IOrientationSensorReading2;
    struct IOrientationSensorReadingChangedEventArgs;
    struct IOrientationSensorReadingYawAccuracy;
    struct IOrientationSensorStatics;
    struct IOrientationSensorStatics2;
    struct IOrientationSensorStatics3;
    struct IOrientationSensorStatics4;
    struct IPedometer;
    struct IPedometer2;
    struct IPedometerDataThresholdFactory;
    struct IPedometerReading;
    struct IPedometerReadingChangedEventArgs;
    struct IPedometerStatics;
    struct IPedometerStatics2;
    struct IProximitySensor;
    struct IProximitySensorDataThresholdFactory;
    struct IProximitySensorReading;
    struct IProximitySensorReadingChangedEventArgs;
    struct IProximitySensorStatics;
    struct IProximitySensorStatics2;
    struct ISensorDataThreshold;
    struct ISensorDataThresholdTriggerDetails;
    struct ISensorQuaternion;
    struct ISensorRotationMatrix;
    struct ISimpleOrientationSensor;
    struct ISimpleOrientationSensor2;
    struct ISimpleOrientationSensorDeviceId;
    struct ISimpleOrientationSensorOrientationChangedEventArgs;
    struct ISimpleOrientationSensorStatics;
    struct ISimpleOrientationSensorStatics2;
    struct IWakeOnApproachOptions;
    struct Accelerometer;
    struct AccelerometerDataThreshold;
    struct AccelerometerReading;
    struct AccelerometerReadingChangedEventArgs;
    struct AccelerometerShakenEventArgs;
    struct ActivitySensor;
    struct ActivitySensorReading;
    struct ActivitySensorReadingChangeReport;
    struct ActivitySensorReadingChangedEventArgs;
    struct ActivitySensorTriggerDetails;
    struct AdaptiveDimmingOptions;
    struct Altimeter;
    struct AltimeterReading;
    struct AltimeterReadingChangedEventArgs;
    struct Barometer;
    struct BarometerDataThreshold;
    struct BarometerReading;
    struct BarometerReadingChangedEventArgs;
    struct Compass;
    struct CompassDataThreshold;
    struct CompassReading;
    struct CompassReadingChangedEventArgs;
    struct Gyrometer;
    struct GyrometerDataThreshold;
    struct GyrometerReading;
    struct GyrometerReadingChangedEventArgs;
    struct HingeAngleReading;
    struct HingeAngleSensor;
    struct HingeAngleSensorReadingChangedEventArgs;
    struct HumanPresenceFeatures;
    struct HumanPresenceSensor;
    struct HumanPresenceSensorReading;
    struct HumanPresenceSensorReadingChangedEventArgs;
    struct HumanPresenceSensorReadingUpdate;
    struct HumanPresenceSettings;
    struct Inclinometer;
    struct InclinometerDataThreshold;
    struct InclinometerReading;
    struct InclinometerReadingChangedEventArgs;
    struct LightSensor;
    struct LightSensorDataThreshold;
    struct LightSensorReading;
    struct LightSensorReadingChangedEventArgs;
    struct LockOnLeaveOptions;
    struct Magnetometer;
    struct MagnetometerDataThreshold;
    struct MagnetometerReading;
    struct MagnetometerReadingChangedEventArgs;
    struct OrientationSensor;
    struct OrientationSensorReading;
    struct OrientationSensorReadingChangedEventArgs;
    struct Pedometer;
    struct PedometerDataThreshold;
    struct PedometerReading;
    struct PedometerReadingChangedEventArgs;
    struct ProximitySensor;
    struct ProximitySensorDataThreshold;
    struct ProximitySensorDisplayOnOffController;
    struct ProximitySensorReading;
    struct ProximitySensorReadingChangedEventArgs;
    struct SensorDataThresholdTriggerDetails;
    struct SensorQuaternion;
    struct SensorRotationMatrix;
    struct SimpleOrientationSensor;
    struct SimpleOrientationSensorOrientationChangedEventArgs;
    struct WakeOnApproachOptions;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometer2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometer3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometer4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometer5>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometerDeviceId>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometerReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometerReading2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometerShakenEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAccelerometerStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IActivitySensor>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IActivitySensorReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangeReport>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IActivitySensorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IActivitySensorTriggerDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAdaptiveDimmingOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAltimeter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAltimeter2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAltimeterReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAltimeterReading2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IAltimeterStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IBarometer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IBarometer2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IBarometer3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IBarometerDataThreshold>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IBarometerReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IBarometerReading2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IBarometerReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IBarometerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IBarometerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ICompass>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ICompass2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ICompass3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ICompass4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ICompassDataThreshold>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ICompassDeviceId>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ICompassReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ICompassReading2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ICompassReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ICompassReadingHeadingAccuracy>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ICompassStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ICompassStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IGyrometer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IGyrometer2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IGyrometer3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IGyrometer4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IGyrometerDataThreshold>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IGyrometerDeviceId>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IGyrometerReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IGyrometerReading2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IGyrometerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IGyrometerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHingeAngleReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHingeAngleSensor>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceFeatures>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceFeatures2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceSensor>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceSensor2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceSettings>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceSettings2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometer2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometer3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometer4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometerDataThreshold>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometerDeviceId>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometerReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometerReading2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometerReadingYawAccuracy>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometerStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IInclinometerStatics4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ILightSensor>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ILightSensor2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ILightSensor3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ILightSensorDataThreshold>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ILightSensorDeviceId>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ILightSensorReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ILightSensorReading2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ILightSensorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ILightSensorStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ILockOnLeaveOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IMagnetometer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IMagnetometer2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IMagnetometer3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IMagnetometer4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IMagnetometerDeviceId>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IMagnetometerReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IMagnetometerReading2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IMagnetometerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IMagnetometerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IOrientationSensor>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IOrientationSensor2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IOrientationSensor3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IOrientationSensorDeviceId>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IOrientationSensorReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IOrientationSensorReading2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IOrientationSensorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IOrientationSensorStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IOrientationSensorStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IOrientationSensorStatics4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IPedometer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IPedometer2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IPedometerDataThresholdFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IPedometerReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IPedometerReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IPedometerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IPedometerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IProximitySensor>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IProximitySensorDataThresholdFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IProximitySensorReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IProximitySensorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IProximitySensorStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ISensorDataThreshold>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ISensorQuaternion>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ISensorRotationMatrix>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::IWakeOnApproachOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Accelerometer>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::AccelerometerDataThreshold>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::AccelerometerReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::AccelerometerShakenEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ActivitySensor>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ActivitySensorReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangeReport>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ActivitySensorTriggerDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::AdaptiveDimmingOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Altimeter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::AltimeterReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::AltimeterReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Barometer>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::BarometerDataThreshold>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::BarometerReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::BarometerReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Compass>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::CompassDataThreshold>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::CompassReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::CompassReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Gyrometer>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::GyrometerDataThreshold>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::GyrometerReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::GyrometerReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::HingeAngleReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::HingeAngleSensor>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::HumanPresenceFeatures>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::HumanPresenceSensor>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::HumanPresenceSensorReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingUpdate>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::HumanPresenceSettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Inclinometer>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::InclinometerDataThreshold>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::InclinometerReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::InclinometerReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::LightSensor>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::LightSensorDataThreshold>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::LightSensorReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::LightSensorReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::LockOnLeaveOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Magnetometer>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::MagnetometerDataThreshold>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::MagnetometerReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::OrientationSensor>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::OrientationSensorReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Pedometer>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::PedometerDataThreshold>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::PedometerReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::PedometerReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ProximitySensor>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ProximitySensorDataThreshold>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ProximitySensorDisplayOnOffController>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ProximitySensorReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::SensorQuaternion>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::SensorRotationMatrix>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::SimpleOrientationSensor>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::WakeOnApproachOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::AccelerometerReadingType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ActivitySensorReadingConfidence>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::ActivityType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::HumanEngagement>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::HumanPresence>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::MagnetometerAccuracy>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::PedometerStepKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::SensorOptimizationGoal>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::SensorReadingType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::SensorType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::SimpleOrientation>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Accelerometer> = L"Windows.Devices.Sensors.Accelerometer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::AccelerometerDataThreshold> = L"Windows.Devices.Sensors.AccelerometerDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::AccelerometerReading> = L"Windows.Devices.Sensors.AccelerometerReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> = L"Windows.Devices.Sensors.AccelerometerReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::AccelerometerShakenEventArgs> = L"Windows.Devices.Sensors.AccelerometerShakenEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ActivitySensor> = L"Windows.Devices.Sensors.ActivitySensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ActivitySensorReading> = L"Windows.Devices.Sensors.ActivitySensorReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangeReport> = L"Windows.Devices.Sensors.ActivitySensorReadingChangeReport";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.ActivitySensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ActivitySensorTriggerDetails> = L"Windows.Devices.Sensors.ActivitySensorTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::AdaptiveDimmingOptions> = L"Windows.Devices.Sensors.AdaptiveDimmingOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Altimeter> = L"Windows.Devices.Sensors.Altimeter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::AltimeterReading> = L"Windows.Devices.Sensors.AltimeterReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> = L"Windows.Devices.Sensors.AltimeterReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Barometer> = L"Windows.Devices.Sensors.Barometer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::BarometerDataThreshold> = L"Windows.Devices.Sensors.BarometerDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::BarometerReading> = L"Windows.Devices.Sensors.BarometerReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::BarometerReadingChangedEventArgs> = L"Windows.Devices.Sensors.BarometerReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Compass> = L"Windows.Devices.Sensors.Compass";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::CompassDataThreshold> = L"Windows.Devices.Sensors.CompassDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::CompassReading> = L"Windows.Devices.Sensors.CompassReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::CompassReadingChangedEventArgs> = L"Windows.Devices.Sensors.CompassReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Gyrometer> = L"Windows.Devices.Sensors.Gyrometer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::GyrometerDataThreshold> = L"Windows.Devices.Sensors.GyrometerDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::GyrometerReading> = L"Windows.Devices.Sensors.GyrometerReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> = L"Windows.Devices.Sensors.GyrometerReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::HingeAngleReading> = L"Windows.Devices.Sensors.HingeAngleReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::HingeAngleSensor> = L"Windows.Devices.Sensors.HingeAngleSensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.HingeAngleSensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::HumanPresenceFeatures> = L"Windows.Devices.Sensors.HumanPresenceFeatures";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::HumanPresenceSensor> = L"Windows.Devices.Sensors.HumanPresenceSensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::HumanPresenceSensorReading> = L"Windows.Devices.Sensors.HumanPresenceSensorReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.HumanPresenceSensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingUpdate> = L"Windows.Devices.Sensors.HumanPresenceSensorReadingUpdate";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::HumanPresenceSettings> = L"Windows.Devices.Sensors.HumanPresenceSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Inclinometer> = L"Windows.Devices.Sensors.Inclinometer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::InclinometerDataThreshold> = L"Windows.Devices.Sensors.InclinometerDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::InclinometerReading> = L"Windows.Devices.Sensors.InclinometerReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> = L"Windows.Devices.Sensors.InclinometerReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::LightSensor> = L"Windows.Devices.Sensors.LightSensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::LightSensorDataThreshold> = L"Windows.Devices.Sensors.LightSensorDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::LightSensorReading> = L"Windows.Devices.Sensors.LightSensorReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.LightSensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::LockOnLeaveOptions> = L"Windows.Devices.Sensors.LockOnLeaveOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Magnetometer> = L"Windows.Devices.Sensors.Magnetometer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::MagnetometerDataThreshold> = L"Windows.Devices.Sensors.MagnetometerDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::MagnetometerReading> = L"Windows.Devices.Sensors.MagnetometerReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> = L"Windows.Devices.Sensors.MagnetometerReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::OrientationSensor> = L"Windows.Devices.Sensors.OrientationSensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::OrientationSensorReading> = L"Windows.Devices.Sensors.OrientationSensorReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.OrientationSensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Pedometer> = L"Windows.Devices.Sensors.Pedometer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::PedometerDataThreshold> = L"Windows.Devices.Sensors.PedometerDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::PedometerReading> = L"Windows.Devices.Sensors.PedometerReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::PedometerReadingChangedEventArgs> = L"Windows.Devices.Sensors.PedometerReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ProximitySensor> = L"Windows.Devices.Sensors.ProximitySensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ProximitySensorDataThreshold> = L"Windows.Devices.Sensors.ProximitySensorDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ProximitySensorDisplayOnOffController> = L"Windows.Devices.Sensors.ProximitySensorDisplayOnOffController";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ProximitySensorReading> = L"Windows.Devices.Sensors.ProximitySensorReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.ProximitySensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails> = L"Windows.Devices.Sensors.SensorDataThresholdTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::SensorQuaternion> = L"Windows.Devices.Sensors.SensorQuaternion";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::SensorRotationMatrix> = L"Windows.Devices.Sensors.SensorRotationMatrix";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::SimpleOrientationSensor> = L"Windows.Devices.Sensors.SimpleOrientationSensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> = L"Windows.Devices.Sensors.SimpleOrientationSensorOrientationChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::WakeOnApproachOptions> = L"Windows.Devices.Sensors.WakeOnApproachOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::AccelerometerReadingType> = L"Windows.Devices.Sensors.AccelerometerReadingType";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ActivitySensorReadingConfidence> = L"Windows.Devices.Sensors.ActivitySensorReadingConfidence";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ActivityType> = L"Windows.Devices.Sensors.ActivityType";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::HumanEngagement> = L"Windows.Devices.Sensors.HumanEngagement";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::HumanPresence> = L"Windows.Devices.Sensors.HumanPresence";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::MagnetometerAccuracy> = L"Windows.Devices.Sensors.MagnetometerAccuracy";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::PedometerStepKind> = L"Windows.Devices.Sensors.PedometerStepKind";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::SensorOptimizationGoal> = L"Windows.Devices.Sensors.SensorOptimizationGoal";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::SensorReadingType> = L"Windows.Devices.Sensors.SensorReadingType";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::SensorType> = L"Windows.Devices.Sensors.SensorType";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::SimpleOrientation> = L"Windows.Devices.Sensors.SimpleOrientation";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometer> = L"Windows.Devices.Sensors.IAccelerometer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometer2> = L"Windows.Devices.Sensors.IAccelerometer2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometer3> = L"Windows.Devices.Sensors.IAccelerometer3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometer4> = L"Windows.Devices.Sensors.IAccelerometer4";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometer5> = L"Windows.Devices.Sensors.IAccelerometer5";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold> = L"Windows.Devices.Sensors.IAccelerometerDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometerDeviceId> = L"Windows.Devices.Sensors.IAccelerometerDeviceId";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometerReading> = L"Windows.Devices.Sensors.IAccelerometerReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometerReading2> = L"Windows.Devices.Sensors.IAccelerometerReading2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs> = L"Windows.Devices.Sensors.IAccelerometerReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometerShakenEventArgs> = L"Windows.Devices.Sensors.IAccelerometerShakenEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometerStatics> = L"Windows.Devices.Sensors.IAccelerometerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometerStatics2> = L"Windows.Devices.Sensors.IAccelerometerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAccelerometerStatics3> = L"Windows.Devices.Sensors.IAccelerometerStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IActivitySensor> = L"Windows.Devices.Sensors.IActivitySensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IActivitySensorReading> = L"Windows.Devices.Sensors.IActivitySensorReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangeReport> = L"Windows.Devices.Sensors.IActivitySensorReadingChangeReport";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.IActivitySensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IActivitySensorStatics> = L"Windows.Devices.Sensors.IActivitySensorStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IActivitySensorTriggerDetails> = L"Windows.Devices.Sensors.IActivitySensorTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAdaptiveDimmingOptions> = L"Windows.Devices.Sensors.IAdaptiveDimmingOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAltimeter> = L"Windows.Devices.Sensors.IAltimeter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAltimeter2> = L"Windows.Devices.Sensors.IAltimeter2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAltimeterReading> = L"Windows.Devices.Sensors.IAltimeterReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAltimeterReading2> = L"Windows.Devices.Sensors.IAltimeterReading2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs> = L"Windows.Devices.Sensors.IAltimeterReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IAltimeterStatics> = L"Windows.Devices.Sensors.IAltimeterStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IBarometer> = L"Windows.Devices.Sensors.IBarometer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IBarometer2> = L"Windows.Devices.Sensors.IBarometer2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IBarometer3> = L"Windows.Devices.Sensors.IBarometer3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IBarometerDataThreshold> = L"Windows.Devices.Sensors.IBarometerDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IBarometerReading> = L"Windows.Devices.Sensors.IBarometerReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IBarometerReading2> = L"Windows.Devices.Sensors.IBarometerReading2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IBarometerReadingChangedEventArgs> = L"Windows.Devices.Sensors.IBarometerReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IBarometerStatics> = L"Windows.Devices.Sensors.IBarometerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IBarometerStatics2> = L"Windows.Devices.Sensors.IBarometerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ICompass> = L"Windows.Devices.Sensors.ICompass";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ICompass2> = L"Windows.Devices.Sensors.ICompass2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ICompass3> = L"Windows.Devices.Sensors.ICompass3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ICompass4> = L"Windows.Devices.Sensors.ICompass4";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ICompassDataThreshold> = L"Windows.Devices.Sensors.ICompassDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ICompassDeviceId> = L"Windows.Devices.Sensors.ICompassDeviceId";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ICompassReading> = L"Windows.Devices.Sensors.ICompassReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ICompassReading2> = L"Windows.Devices.Sensors.ICompassReading2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ICompassReadingChangedEventArgs> = L"Windows.Devices.Sensors.ICompassReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ICompassReadingHeadingAccuracy> = L"Windows.Devices.Sensors.ICompassReadingHeadingAccuracy";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ICompassStatics> = L"Windows.Devices.Sensors.ICompassStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ICompassStatics2> = L"Windows.Devices.Sensors.ICompassStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IGyrometer> = L"Windows.Devices.Sensors.IGyrometer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IGyrometer2> = L"Windows.Devices.Sensors.IGyrometer2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IGyrometer3> = L"Windows.Devices.Sensors.IGyrometer3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IGyrometer4> = L"Windows.Devices.Sensors.IGyrometer4";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IGyrometerDataThreshold> = L"Windows.Devices.Sensors.IGyrometerDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IGyrometerDeviceId> = L"Windows.Devices.Sensors.IGyrometerDeviceId";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IGyrometerReading> = L"Windows.Devices.Sensors.IGyrometerReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IGyrometerReading2> = L"Windows.Devices.Sensors.IGyrometerReading2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs> = L"Windows.Devices.Sensors.IGyrometerReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IGyrometerStatics> = L"Windows.Devices.Sensors.IGyrometerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IGyrometerStatics2> = L"Windows.Devices.Sensors.IGyrometerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHingeAngleReading> = L"Windows.Devices.Sensors.IHingeAngleReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHingeAngleSensor> = L"Windows.Devices.Sensors.IHingeAngleSensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.IHingeAngleSensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics> = L"Windows.Devices.Sensors.IHingeAngleSensorStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceFeatures> = L"Windows.Devices.Sensors.IHumanPresenceFeatures";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceFeatures2> = L"Windows.Devices.Sensors.IHumanPresenceFeatures2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensor> = L"Windows.Devices.Sensors.IHumanPresenceSensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensor2> = L"Windows.Devices.Sensors.IHumanPresenceSensor2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension> = L"Windows.Devices.Sensors.IHumanPresenceSensorExtension";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading> = L"Windows.Devices.Sensors.IHumanPresenceSensorReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading2> = L"Windows.Devices.Sensors.IHumanPresenceSensorReading2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.IHumanPresenceSensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate> = L"Windows.Devices.Sensors.IHumanPresenceSensorReadingUpdate";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics> = L"Windows.Devices.Sensors.IHumanPresenceSensorStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics2> = L"Windows.Devices.Sensors.IHumanPresenceSensorStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceSettings> = L"Windows.Devices.Sensors.IHumanPresenceSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceSettings2> = L"Windows.Devices.Sensors.IHumanPresenceSettings2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics> = L"Windows.Devices.Sensors.IHumanPresenceSettingsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometer> = L"Windows.Devices.Sensors.IInclinometer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometer2> = L"Windows.Devices.Sensors.IInclinometer2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometer3> = L"Windows.Devices.Sensors.IInclinometer3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometer4> = L"Windows.Devices.Sensors.IInclinometer4";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometerDataThreshold> = L"Windows.Devices.Sensors.IInclinometerDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometerDeviceId> = L"Windows.Devices.Sensors.IInclinometerDeviceId";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometerReading> = L"Windows.Devices.Sensors.IInclinometerReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometerReading2> = L"Windows.Devices.Sensors.IInclinometerReading2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs> = L"Windows.Devices.Sensors.IInclinometerReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometerReadingYawAccuracy> = L"Windows.Devices.Sensors.IInclinometerReadingYawAccuracy";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometerStatics> = L"Windows.Devices.Sensors.IInclinometerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometerStatics2> = L"Windows.Devices.Sensors.IInclinometerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometerStatics3> = L"Windows.Devices.Sensors.IInclinometerStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IInclinometerStatics4> = L"Windows.Devices.Sensors.IInclinometerStatics4";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ILightSensor> = L"Windows.Devices.Sensors.ILightSensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ILightSensor2> = L"Windows.Devices.Sensors.ILightSensor2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ILightSensor3> = L"Windows.Devices.Sensors.ILightSensor3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ILightSensorDataThreshold> = L"Windows.Devices.Sensors.ILightSensorDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ILightSensorDeviceId> = L"Windows.Devices.Sensors.ILightSensorDeviceId";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ILightSensorReading> = L"Windows.Devices.Sensors.ILightSensorReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ILightSensorReading2> = L"Windows.Devices.Sensors.ILightSensorReading2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.ILightSensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ILightSensorStatics> = L"Windows.Devices.Sensors.ILightSensorStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ILightSensorStatics2> = L"Windows.Devices.Sensors.ILightSensorStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ILockOnLeaveOptions> = L"Windows.Devices.Sensors.ILockOnLeaveOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IMagnetometer> = L"Windows.Devices.Sensors.IMagnetometer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IMagnetometer2> = L"Windows.Devices.Sensors.IMagnetometer2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IMagnetometer3> = L"Windows.Devices.Sensors.IMagnetometer3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IMagnetometer4> = L"Windows.Devices.Sensors.IMagnetometer4";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold> = L"Windows.Devices.Sensors.IMagnetometerDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IMagnetometerDeviceId> = L"Windows.Devices.Sensors.IMagnetometerDeviceId";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IMagnetometerReading> = L"Windows.Devices.Sensors.IMagnetometerReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IMagnetometerReading2> = L"Windows.Devices.Sensors.IMagnetometerReading2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs> = L"Windows.Devices.Sensors.IMagnetometerReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IMagnetometerStatics> = L"Windows.Devices.Sensors.IMagnetometerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IMagnetometerStatics2> = L"Windows.Devices.Sensors.IMagnetometerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IOrientationSensor> = L"Windows.Devices.Sensors.IOrientationSensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IOrientationSensor2> = L"Windows.Devices.Sensors.IOrientationSensor2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IOrientationSensor3> = L"Windows.Devices.Sensors.IOrientationSensor3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IOrientationSensorDeviceId> = L"Windows.Devices.Sensors.IOrientationSensorDeviceId";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IOrientationSensorReading> = L"Windows.Devices.Sensors.IOrientationSensorReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IOrientationSensorReading2> = L"Windows.Devices.Sensors.IOrientationSensorReading2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.IOrientationSensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy> = L"Windows.Devices.Sensors.IOrientationSensorReadingYawAccuracy";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IOrientationSensorStatics> = L"Windows.Devices.Sensors.IOrientationSensorStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IOrientationSensorStatics2> = L"Windows.Devices.Sensors.IOrientationSensorStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IOrientationSensorStatics3> = L"Windows.Devices.Sensors.IOrientationSensorStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IOrientationSensorStatics4> = L"Windows.Devices.Sensors.IOrientationSensorStatics4";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IPedometer> = L"Windows.Devices.Sensors.IPedometer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IPedometer2> = L"Windows.Devices.Sensors.IPedometer2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IPedometerDataThresholdFactory> = L"Windows.Devices.Sensors.IPedometerDataThresholdFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IPedometerReading> = L"Windows.Devices.Sensors.IPedometerReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IPedometerReadingChangedEventArgs> = L"Windows.Devices.Sensors.IPedometerReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IPedometerStatics> = L"Windows.Devices.Sensors.IPedometerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IPedometerStatics2> = L"Windows.Devices.Sensors.IPedometerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IProximitySensor> = L"Windows.Devices.Sensors.IProximitySensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IProximitySensorDataThresholdFactory> = L"Windows.Devices.Sensors.IProximitySensorDataThresholdFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IProximitySensorReading> = L"Windows.Devices.Sensors.IProximitySensorReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.IProximitySensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IProximitySensorStatics> = L"Windows.Devices.Sensors.IProximitySensorStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IProximitySensorStatics2> = L"Windows.Devices.Sensors.IProximitySensorStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ISensorDataThreshold> = L"Windows.Devices.Sensors.ISensorDataThreshold";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails> = L"Windows.Devices.Sensors.ISensorDataThresholdTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ISensorQuaternion> = L"Windows.Devices.Sensors.ISensorQuaternion";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ISensorRotationMatrix> = L"Windows.Devices.Sensors.ISensorRotationMatrix";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor> = L"Windows.Devices.Sensors.ISimpleOrientationSensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor2> = L"Windows.Devices.Sensors.ISimpleOrientationSensor2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId> = L"Windows.Devices.Sensors.ISimpleOrientationSensorDeviceId";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs> = L"Windows.Devices.Sensors.ISimpleOrientationSensorOrientationChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics> = L"Windows.Devices.Sensors.ISimpleOrientationSensorStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics2> = L"Windows.Devices.Sensors.ISimpleOrientationSensorStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::IWakeOnApproachOptions> = L"Windows.Devices.Sensors.IWakeOnApproachOptions";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometer>{ 0xDF184548,0x2711,0x4DA7,{ 0x80,0x98,0x4B,0x82,0x20,0x5D,0x3C,0x7D } }; // DF184548-2711-4DA7-8098-4B82205D3C7D
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometer2>{ 0xE8F092EE,0x4964,0x401A,{ 0xB6,0x02,0x22,0x0D,0x71,0x53,0xC6,0x0A } }; // E8F092EE-4964-401A-B602-220D7153C60A
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometer3>{ 0x87E0022A,0xED80,0x49EB,{ 0xBF,0x8A,0xA4,0xEA,0x31,0xE5,0xCD,0x84 } }; // 87E0022A-ED80-49EB-BF8A-A4EA31E5CD84
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometer4>{ 0x1D373C4F,0x42D3,0x45B2,{ 0x81,0x44,0xAB,0x7F,0xB6,0x65,0xEB,0x59 } }; // 1D373C4F-42D3-45B2-8144-AB7FB665EB59
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometer5>{ 0x7E7E7021,0xDEF4,0x53A6,{ 0xAF,0x43,0x80,0x6F,0xD5,0x38,0xED,0xF6 } }; // 7E7E7021-DEF4-53A6-AF43-806FD538EDF6
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold>{ 0xF92C1B68,0x6320,0x5577,{ 0x87,0x9E,0x99,0x42,0x62,0x1C,0x3D,0xD9 } }; // F92C1B68-6320-5577-879E-9942621C3DD9
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometerDeviceId>{ 0x7EAC64A9,0x97D5,0x446D,{ 0xAB,0x5A,0x91,0x7D,0xF9,0xB9,0x6A,0x2C } }; // 7EAC64A9-97D5-446D-AB5A-917DF9B96A2C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometerReading>{ 0xB9FE7ACB,0xD351,0x40AF,{ 0x8B,0xB6,0x7A,0xA9,0xAE,0x64,0x1F,0xB7 } }; // B9FE7ACB-D351-40AF-8BB6-7AA9AE641FB7
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometerReading2>{ 0x0A864AA2,0x15AE,0x4A40,{ 0xBE,0x55,0xDB,0x58,0xD7,0xDE,0x73,0x89 } }; // 0A864AA2-15AE-4A40-BE55-DB58D7DE7389
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs>{ 0x0095C65B,0xB6AC,0x475A,{ 0x9F,0x44,0x8B,0x32,0xD3,0x5A,0x3F,0x25 } }; // 0095C65B-B6AC-475A-9F44-8B32D35A3F25
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometerShakenEventArgs>{ 0x95FF01D1,0x4A28,0x4F35,{ 0x98,0xE8,0x81,0x78,0xAA,0xE4,0x08,0x4A } }; // 95FF01D1-4A28-4F35-98E8-8178AAE4084A
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometerStatics>{ 0xA5E28B74,0x5A87,0x4A2D,{ 0xBE,0xCC,0x0F,0x90,0x6E,0xA0,0x61,0xDD } }; // A5E28B74-5A87-4A2D-BECC-0F906EA061DD
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometerStatics2>{ 0xC4C4842F,0xD86B,0x4685,{ 0xB2,0xD7,0x33,0x96,0xF7,0x98,0xD5,0x7B } }; // C4C4842F-D86B-4685-B2D7-3396F798D57B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAccelerometerStatics3>{ 0x9DE218CF,0x455D,0x4CF3,{ 0x82,0x00,0x70,0xE1,0x41,0x03,0x40,0xF8 } }; // 9DE218CF-455D-4CF3-8200-70E1410340F8
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IActivitySensor>{ 0xCD7A630C,0xFB5F,0x48EB,{ 0xB0,0x9B,0xA2,0x70,0x8D,0x1C,0x61,0xEF } }; // CD7A630C-FB5F-48EB-B09B-A2708D1C61EF
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IActivitySensorReading>{ 0x85125A96,0x1472,0x40A2,{ 0xB2,0xAE,0xE1,0xEF,0x29,0x22,0x6C,0x78 } }; // 85125A96-1472-40A2-B2AE-E1EF29226C78
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangeReport>{ 0x4F3C2915,0xD93B,0x47BD,{ 0x96,0x0A,0xF2,0x0F,0xB2,0xF3,0x22,0xB9 } }; // 4F3C2915-D93B-47BD-960A-F20FB2F322B9
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs>{ 0xDE386717,0xAEB6,0x4EC7,{ 0x94,0x6A,0xD9,0xCC,0x19,0xB9,0x51,0xEC } }; // DE386717-AEB6-4EC7-946A-D9CC19B951EC
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IActivitySensorStatics>{ 0xA71E0E9D,0xEE8B,0x45D1,{ 0xB2,0x5B,0x08,0xCC,0x0D,0xF9,0x2A,0xB6 } }; // A71E0E9D-EE8B-45D1-B25B-08CC0DF92AB6
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IActivitySensorTriggerDetails>{ 0x2C9E6612,0xB9CA,0x4677,{ 0xB2,0x63,0x24,0x32,0x97,0xF7,0x9D,0x3A } }; // 2C9E6612-B9CA-4677-B263-243297F79D3A
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAdaptiveDimmingOptions>{ 0xD3213CF7,0x89B5,0x5732,{ 0xB2,0xA0,0xAE,0xFE,0x32,0x4F,0x54,0xE6 } }; // D3213CF7-89B5-5732-B2A0-AEFE324F54E6
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAltimeter>{ 0x72F057FD,0x8F04,0x49F1,{ 0xB4,0xA7,0xF4,0xE3,0x63,0xB7,0x01,0xA2 } }; // 72F057FD-8F04-49F1-B4A7-F4E363B701A2
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAltimeter2>{ 0xC9471BF9,0x2ADD,0x48F5,{ 0x9F,0x08,0x3D,0x0C,0x76,0x60,0xD9,0x38 } }; // C9471BF9-2ADD-48F5-9F08-3D0C7660D938
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAltimeterReading>{ 0xFBE8EF73,0x7F5E,0x48C8,{ 0xAA,0x1A,0xF1,0xF3,0xBE,0xFC,0x11,0x44 } }; // FBE8EF73-7F5E-48C8-AA1A-F1F3BEFC1144
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAltimeterReading2>{ 0x543A1BD9,0x6D0B,0x42B2,{ 0xBD,0x69,0xBC,0x8F,0xAE,0x0F,0x78,0x2C } }; // 543A1BD9-6D0B-42B2-BD69-BC8FAE0F782C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs>{ 0x7069D077,0x446D,0x47F7,{ 0x99,0x8C,0xEB,0xC2,0x3B,0x45,0xE4,0xA2 } }; // 7069D077-446D-47F7-998C-EBC23B45E4A2
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IAltimeterStatics>{ 0x9EB4D7C3,0xE5AC,0x47CE,{ 0x8E,0xEF,0xD3,0x71,0x81,0x68,0xC0,0x1F } }; // 9EB4D7C3-E5AC-47CE-8EEF-D3718168C01F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IBarometer>{ 0x934475A8,0x78BF,0x452F,{ 0xB0,0x17,0xF0,0x20,0x9C,0xE6,0xDA,0xB4 } }; // 934475A8-78BF-452F-B017-F0209CE6DAB4
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IBarometer2>{ 0x32BCC418,0x3EEB,0x4D04,{ 0x95,0x74,0x76,0x33,0xA8,0x78,0x1F,0x9F } }; // 32BCC418-3EEB-4D04-9574-7633A8781F9F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IBarometer3>{ 0x0E35F0EA,0x02B5,0x5A04,{ 0xB0,0x3D,0x82,0x20,0x84,0x86,0x3A,0x54 } }; // 0E35F0EA-02B5-5A04-B03D-822084863A54
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IBarometerDataThreshold>{ 0x076B952C,0xCB62,0x5A90,{ 0xA0,0xD1,0xF8,0x5E,0x4A,0x93,0x63,0x94 } }; // 076B952C-CB62-5A90-A0D1-F85E4A936394
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IBarometerReading>{ 0xF5B9D2E6,0x1DF6,0x4A1A,{ 0xA7,0xAD,0x32,0x1D,0x4F,0x5D,0xB2,0x47 } }; // F5B9D2E6-1DF6-4A1A-A7AD-321D4F5DB247
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IBarometerReading2>{ 0x85A244EB,0x90C5,0x4875,{ 0x89,0x1C,0x38,0x65,0xB4,0xC3,0x57,0xE7 } }; // 85A244EB-90C5-4875-891C-3865B4C357E7
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IBarometerReadingChangedEventArgs>{ 0x3D84945F,0x037B,0x404F,{ 0x9B,0xBB,0x62,0x32,0xD6,0x95,0x43,0xC3 } }; // 3D84945F-037B-404F-9BBB-6232D69543C3
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IBarometerStatics>{ 0x286B270A,0x02E3,0x4F86,{ 0x84,0xFC,0xFD,0xD8,0x92,0xB5,0x94,0x0F } }; // 286B270A-02E3-4F86-84FC-FDD892B5940F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IBarometerStatics2>{ 0x8FC6B1E7,0x95FF,0x44AC,{ 0x87,0x8E,0xD6,0x5C,0x83,0x08,0xC3,0x4C } }; // 8FC6B1E7-95FF-44AC-878E-D65C8308C34C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ICompass>{ 0x292FFA94,0x1B45,0x403C,{ 0xBA,0x06,0xB1,0x06,0xDB,0xA6,0x9A,0x64 } }; // 292FFA94-1B45-403C-BA06-B106DBA69A64
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ICompass2>{ 0x36F26D09,0xC7D7,0x434F,{ 0xB4,0x61,0x97,0x9D,0xDF,0xC2,0x32,0x2F } }; // 36F26D09-C7D7-434F-B461-979DDFC2322F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ICompass3>{ 0xA424801B,0xC5EA,0x4D45,{ 0xA0,0xEC,0x4B,0x79,0x1F,0x04,0x1A,0x89 } }; // A424801B-C5EA-4D45-A0EC-4B791F041A89
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ICompass4>{ 0x291E7F11,0xEC32,0x5DCC,{ 0xBF,0xCB,0x0B,0xB3,0x9E,0xBA,0x57,0x74 } }; // 291E7F11-EC32-5DCC-BFCB-0BB39EBA5774
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ICompassDataThreshold>{ 0xD15B52B3,0xD39D,0x5EC8,{ 0xB2,0xE4,0xF1,0x93,0xE6,0xAB,0x34,0xED } }; // D15B52B3-D39D-5EC8-B2E4-F193E6AB34ED
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ICompassDeviceId>{ 0xD181CA29,0xB085,0x4B1D,{ 0x87,0x0A,0x4F,0xF5,0x7B,0xA7,0x4F,0xD4 } }; // D181CA29-B085-4B1D-870A-4FF57BA74FD4
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ICompassReading>{ 0x82911128,0x513D,0x4DC9,{ 0xB7,0x81,0x5E,0xED,0xFB,0xF0,0x2D,0x0C } }; // 82911128-513D-4DC9-B781-5EEDFBF02D0C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ICompassReading2>{ 0xB13A661E,0x51BB,0x4A12,{ 0xBE,0xDD,0xAD,0x47,0xFF,0x87,0xD2,0xE8 } }; // B13A661E-51BB-4A12-BEDD-AD47FF87D2E8
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ICompassReadingChangedEventArgs>{ 0x8F1549B0,0xE8BC,0x4C7E,{ 0xB0,0x09,0x4E,0x41,0xDF,0x13,0x70,0x72 } }; // 8F1549B0-E8BC-4C7E-B009-4E41DF137072
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ICompassReadingHeadingAccuracy>{ 0xE761354E,0x8911,0x40F7,{ 0x9E,0x16,0x6E,0xCC,0x7D,0xAE,0xC5,0xDE } }; // E761354E-8911-40F7-9E16-6ECC7DAEC5DE
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ICompassStatics>{ 0x9ABC97DF,0x56EC,0x4C25,{ 0xB5,0x4D,0x40,0xA6,0x8B,0xB5,0xB2,0x69 } }; // 9ABC97DF-56EC-4C25-B54D-40A68BB5B269
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ICompassStatics2>{ 0x0ACE0EAD,0x3BAA,0x4990,{ 0x9C,0xE4,0xBE,0x09,0x13,0x75,0x4E,0xD2 } }; // 0ACE0EAD-3BAA-4990-9CE4-BE0913754ED2
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IGyrometer>{ 0xFDB9A9C4,0x84B1,0x4CA2,{ 0x97,0x63,0x9B,0x58,0x95,0x06,0xC7,0x0C } }; // FDB9A9C4-84B1-4CA2-9763-9B589506C70C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IGyrometer2>{ 0x63DF2443,0x8CE8,0x41C3,{ 0xAC,0x44,0x86,0x98,0x81,0x0B,0x55,0x7F } }; // 63DF2443-8CE8-41C3-AC44-8698810B557F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IGyrometer3>{ 0x5D6F88D5,0x8FBC,0x4484,{ 0x91,0x4B,0x52,0x8A,0xDF,0xD9,0x47,0xB1 } }; // 5D6F88D5-8FBC-4484-914B-528ADFD947B1
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IGyrometer4>{ 0x0628A60C,0x4C4B,0x5096,{ 0x94,0xE6,0xC3,0x56,0xDF,0x68,0xBE,0xF7 } }; // 0628A60C-4C4B-5096-94E6-C356DF68BEF7
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IGyrometerDataThreshold>{ 0x8648B31E,0x6E52,0x5259,{ 0xBB,0xAD,0x24,0x2A,0x69,0xDC,0x38,0xC8 } }; // 8648B31E-6E52-5259-BBAD-242A69DC38C8
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IGyrometerDeviceId>{ 0x1EE5E978,0x89A2,0x4275,{ 0x9E,0x95,0x71,0x26,0xF4,0x70,0x87,0x60 } }; // 1EE5E978-89A2-4275-9E95-7126F4708760
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IGyrometerReading>{ 0xB3D6DE5C,0x1EE4,0x456F,{ 0x9D,0xE7,0xE2,0x49,0x3B,0x5C,0x8E,0x03 } }; // B3D6DE5C-1EE4-456F-9DE7-E2493B5C8E03
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IGyrometerReading2>{ 0x16AFE13C,0x2B89,0x44BB,{ 0x82,0x2B,0xD1,0xE1,0x55,0x6F,0xF0,0x9B } }; // 16AFE13C-2B89-44BB-822B-D1E1556FF09B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs>{ 0x0FDF1895,0x6F9E,0x42CE,{ 0x8D,0x58,0x38,0x8C,0x0A,0xB8,0x35,0x6D } }; // 0FDF1895-6F9E-42CE-8D58-388C0AB8356D
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IGyrometerStatics>{ 0x83B6E7C9,0xE49D,0x4B39,{ 0x86,0xE6,0xCD,0x55,0x4B,0xE4,0xC5,0xC1 } }; // 83B6E7C9-E49D-4B39-86E6-CD554BE4C5C1
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IGyrometerStatics2>{ 0xEF83F7A1,0xD700,0x4204,{ 0x96,0x13,0x79,0xC6,0xB1,0x61,0xDF,0x4E } }; // EF83F7A1-D700-4204-9613-79C6B161DF4E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHingeAngleReading>{ 0xA3CD45B9,0x1BF1,0x4F65,{ 0xA7,0x04,0xE2,0xDA,0x04,0xF1,0x82,0xC0 } }; // A3CD45B9-1BF1-4F65-A704-E2DA04F182C0
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHingeAngleSensor>{ 0xE9D3BE02,0xBFDF,0x437F,{ 0x8C,0x29,0x88,0xC7,0x73,0x93,0xD3,0x09 } }; // E9D3BE02-BFDF-437F-8C29-88C77393D309
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs>{ 0x24D9558B,0xFAD0,0x42B8,{ 0xA8,0x54,0x78,0x92,0x30,0x49,0xA1,0xBA } }; // 24D9558B-FAD0-42B8-A854-78923049A1BA
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics>{ 0xB7B63910,0xFBB1,0x4123,{ 0x89,0xCE,0x4E,0xA3,0x4E,0xB0,0xDF,0xCA } }; // B7B63910-FBB1-4123-89CE-4EA34EB0DFCA
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceFeatures>{ 0xBDB09FDA,0x3244,0x557A,{ 0xBD,0x29,0x8B,0x00,0x4F,0x59,0xF2,0xCC } }; // BDB09FDA-3244-557A-BD29-8B004F59F2CC
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceFeatures2>{ 0x08A9CDDA,0xD929,0x5EC2,{ 0x81,0xE2,0x94,0x0B,0xAF,0xA0,0x89,0xCF } }; // 08A9CDDA-D929-5EC2-81E2-940BAFA089CF
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensor>{ 0x2116788B,0xE389,0x5CC3,{ 0x9A,0x97,0xCB,0x17,0xBE,0x10,0x08,0xBD } }; // 2116788B-E389-5CC3-9A97-CB17BE1008BD
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensor2>{ 0xF8833779,0x65FE,0x541A,{ 0xB9,0xD6,0x1E,0x47,0x4A,0x48,0x5E,0x7A } }; // F8833779-65FE-541A-B9D6-1E474A485E7A
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension>{ 0x3E526A71,0x2D1D,0x5D43,{ 0x8A,0x8E,0xA4,0x34,0xA8,0x24,0x2E,0xF0 } }; // 3E526A71-2D1D-5D43-8A8E-A434A8242EF0
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading>{ 0x83533BF5,0xA85A,0x5D50,{ 0x8B,0xE4,0x60,0x72,0xD7,0x45,0xA3,0xBB } }; // 83533BF5-A85A-5D50-8BE4-6072D745A3BB
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading2>{ 0xC4F0E950,0x3BFF,0x53D6,{ 0xA0,0xF8,0x51,0x4E,0xA3,0x70,0x5C,0x66 } }; // C4F0E950-3BFF-53D6-A0F8-514EA3705C66
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingChangedEventArgs>{ 0xA9DC4583,0xFD69,0x5C5E,{ 0xAB,0x1F,0x94,0x22,0x04,0xEA,0xE2,0xDB } }; // A9DC4583-FD69-5C5E-AB1F-942204EAE2DB
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate>{ 0x42419C77,0x6D2F,0x55A0,{ 0x9E,0x01,0xC9,0xCB,0xE7,0xB2,0xD6,0xDF } }; // 42419C77-6D2F-55A0-9E01-C9CBE7B2D6DF
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics>{ 0x2AE89842,0xDBA9,0x56B2,{ 0x9F,0x27,0xEA,0xC6,0x9D,0x62,0x10,0x04 } }; // 2AE89842-DBA9-56B2-9F27-EAC69D621004
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics2>{ 0x5DE35843,0xD260,0x5A87,{ 0x99,0x5E,0xAC,0xE9,0x13,0x26,0xE1,0xC4 } }; // 5DE35843-D260-5A87-995E-ACE91326E1C4
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceSettings>{ 0xEF4DAF5B,0x07B7,0x5EB6,{ 0x86,0xBB,0xB7,0xFF,0x49,0xCE,0x44,0xFB } }; // EF4DAF5B-07B7-5EB6-86BB-B7FF49CE44FB
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceSettings2>{ 0xA26F705E,0x8696,0x5EB4,{ 0xB9,0xE1,0x26,0xA5,0x08,0xDE,0x1C,0xD4 } }; // A26F705E-8696-5EB4-B9E1-26A508DE1CD4
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics>{ 0x7F343202,0xE010,0x52C4,{ 0xAF,0x0C,0x04,0xA8,0xF1,0xE0,0x33,0xDA } }; // 7F343202-E010-52C4-AF0C-04A8F1E033DA
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometer>{ 0x2648CA6F,0x2286,0x406F,{ 0x91,0x61,0xF0,0xC4,0xBD,0x80,0x6E,0xBF } }; // 2648CA6F-2286-406F-9161-F0C4BD806EBF
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometer2>{ 0x029F3393,0x28B2,0x45F8,{ 0xBB,0x16,0x61,0xE8,0x6A,0x7F,0xAE,0x6E } }; // 029F3393-28B2-45F8-BB16-61E86A7FAE6E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometer3>{ 0x3A095004,0xD765,0x4384,{ 0xA3,0xD7,0x02,0x83,0xF3,0xAB,0xE6,0xAE } }; // 3A095004-D765-4384-A3D7-0283F3ABE6AE
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometer4>{ 0x43852618,0x8FCA,0x548E,{ 0xBB,0xF5,0x5C,0x50,0x41,0x2B,0x6A,0xA4 } }; // 43852618-8FCA-548E-BBF5-5C50412B6AA4
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometerDataThreshold>{ 0xF80A4783,0x7BFE,0x545E,{ 0xBB,0x60,0xA0,0xEB,0xC4,0x7B,0xD2,0xFB } }; // F80A4783-7BFE-545E-BB60-A0EBC47BD2FB
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometerDeviceId>{ 0x01E91982,0x41FF,0x4406,{ 0xAE,0x83,0x62,0x21,0x0F,0xF1,0x6F,0xE3 } }; // 01E91982-41FF-4406-AE83-62210FF16FE3
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometerReading>{ 0x9F44F055,0xB6F6,0x497F,{ 0xB1,0x27,0x1A,0x77,0x5E,0x50,0x14,0x58 } }; // 9F44F055-B6F6-497F-B127-1A775E501458
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometerReading2>{ 0x4F164781,0xE90B,0x4658,{ 0x89,0x15,0x01,0x03,0xE0,0x8A,0x80,0x5A } }; // 4F164781-E90B-4658-8915-0103E08A805A
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs>{ 0x4AE91DC1,0xE7EB,0x4938,{ 0x85,0x11,0xAE,0x0D,0x6B,0x44,0x04,0x38 } }; // 4AE91DC1-E7EB-4938-8511-AE0D6B440438
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometerReadingYawAccuracy>{ 0xB453E880,0x1FE3,0x4986,{ 0xA2,0x57,0xE6,0xEC,0xE2,0x72,0x39,0x49 } }; // B453E880-1FE3-4986-A257-E6ECE2723949
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometerStatics>{ 0xF22EC551,0x9C30,0x453A,{ 0x8B,0x49,0x3C,0x3E,0xEB,0x33,0xCB,0x61 } }; // F22EC551-9C30-453A-8B49-3C3EEB33CB61
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometerStatics2>{ 0x043F9775,0x6A1E,0x499C,{ 0x86,0xE0,0x63,0x8C,0x1A,0x86,0x4B,0x00 } }; // 043F9775-6A1E-499C-86E0-638C1A864B00
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometerStatics3>{ 0xBD9A4280,0xB91A,0x4829,{ 0x93,0x92,0xAB,0xC0,0xB6,0xBD,0xF2,0xB4 } }; // BD9A4280-B91A-4829-9392-ABC0B6BDF2B4
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IInclinometerStatics4>{ 0xE8BA96F9,0x6E85,0x4A83,{ 0xAE,0xD0,0xD7,0xCD,0xCC,0x98,0x56,0xC8 } }; // E8BA96F9-6E85-4A83-AED0-D7CDCC9856C8
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ILightSensor>{ 0xF84C0718,0x0C54,0x47AE,{ 0x92,0x2E,0x78,0x9F,0x57,0xFB,0x03,0xA0 } }; // F84C0718-0C54-47AE-922E-789F57FB03A0
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ILightSensor2>{ 0x486B24E8,0xA94C,0x4090,{ 0x8F,0x48,0x09,0xF7,0x82,0xA9,0xF7,0xD5 } }; // 486B24E8-A94C-4090-8F48-09F782A9F7D5
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ILightSensor3>{ 0x4876D0FF,0x9F4C,0x5F72,{ 0xAD,0xBD,0xA3,0x47,0x1B,0x06,0x3C,0x00 } }; // 4876D0FF-9F4C-5F72-ADBD-A3471B063C00
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ILightSensorDataThreshold>{ 0xB160AFD1,0x878F,0x5492,{ 0x9F,0x2C,0x33,0xDC,0x3A,0xE5,0x84,0xA3 } }; // B160AFD1-878F-5492-9F2C-33DC3AE584A3
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ILightSensorDeviceId>{ 0x7FEE49F8,0x0AFB,0x4F51,{ 0x87,0xF0,0x6C,0x26,0x37,0x5C,0xE9,0x4F } }; // 7FEE49F8-0AFB-4F51-87F0-6C26375CE94F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ILightSensorReading>{ 0xFFDF6300,0x227C,0x4D2B,{ 0xB3,0x02,0xFC,0x01,0x42,0x48,0x5C,0x68 } }; // FFDF6300-227C-4D2B-B302-FC0142485C68
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ILightSensorReading2>{ 0xB7512185,0x44A3,0x44C9,{ 0x81,0x90,0x9E,0xF6,0xDE,0x0A,0x8A,0x74 } }; // B7512185-44A3-44C9-8190-9EF6DE0A8A74
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs>{ 0xA3A2F4CF,0x258B,0x420C,{ 0xB8,0xAB,0x8E,0xDD,0x60,0x1E,0xCF,0x50 } }; // A3A2F4CF-258B-420C-B8AB-8EDD601ECF50
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ILightSensorStatics>{ 0x45DB8C84,0xC3A8,0x471E,{ 0x9A,0x53,0x64,0x57,0xFA,0xD8,0x7C,0x0E } }; // 45DB8C84-C3A8-471E-9A53-6457FAD87C0E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ILightSensorStatics2>{ 0x0EC0A650,0xDDC6,0x40AB,{ 0xAC,0xE3,0xEC,0x33,0x59,0xD4,0x2C,0x51 } }; // 0EC0A650-DDC6-40AB-ACE3-EC3359D42C51
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ILockOnLeaveOptions>{ 0x3C6BF8BD,0x04C1,0x5829,{ 0x8D,0x4E,0x70,0x52,0x17,0x55,0xB8,0xBE } }; // 3C6BF8BD-04C1-5829-8D4E-70521755B8BE
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IMagnetometer>{ 0x484F626E,0xD3C9,0x4111,{ 0xB3,0xF6,0x2C,0xF1,0xFA,0xA4,0x18,0xD5 } }; // 484F626E-D3C9-4111-B3F6-2CF1FAA418D5
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IMagnetometer2>{ 0xB4656C85,0x26F6,0x444B,{ 0xA9,0xE2,0xA2,0x3F,0x96,0x6C,0xD3,0x68 } }; // B4656C85-26F6-444B-A9E2-A23F966CD368
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IMagnetometer3>{ 0xBE93DB7C,0xA625,0x48EF,{ 0xAC,0xF7,0xFA,0xC1,0x04,0x83,0x26,0x71 } }; // BE93DB7C-A625-48EF-ACF7-FAC104832671
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IMagnetometer4>{ 0xDFB17901,0x3E0F,0x508F,{ 0xB2,0x4B,0xF2,0xBB,0x75,0x01,0x5F,0x40 } }; // DFB17901-3E0F-508F-B24B-F2BB75015F40
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold>{ 0xD177CB01,0x9063,0x5FA5,{ 0xB5,0x96,0xB4,0x45,0xE9,0xDC,0x34,0x01 } }; // D177CB01-9063-5FA5-B596-B445E9DC3401
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IMagnetometerDeviceId>{ 0x58B498C2,0x7E4B,0x404C,{ 0x9F,0xC5,0x5D,0xE8,0xB4,0x0E,0xBA,0xE3 } }; // 58B498C2-7E4B-404C-9FC5-5DE8B40EBAE3
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IMagnetometerReading>{ 0x0C2CC40D,0xEBFD,0x4E5C,{ 0xBB,0x11,0xAF,0xC2,0x9B,0x3C,0xAE,0x61 } }; // 0C2CC40D-EBFD-4E5C-BB11-AFC29B3CAE61
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IMagnetometerReading2>{ 0xD4C95C61,0x61D9,0x404B,{ 0xA3,0x28,0x06,0x6F,0x17,0x7A,0x14,0x09 } }; // D4C95C61-61D9-404B-A328-066F177A1409
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs>{ 0x17EAE872,0x2EB9,0x4EE7,{ 0x8A,0xD0,0x31,0x27,0x53,0x7D,0x94,0x9B } }; // 17EAE872-2EB9-4EE7-8AD0-3127537D949B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IMagnetometerStatics>{ 0x853C64CC,0x0698,0x4DDA,{ 0xA6,0xDF,0x9C,0xB9,0xCC,0x4A,0xB4,0x0A } }; // 853C64CC-0698-4DDA-A6DF-9CB9CC4AB40A
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IMagnetometerStatics2>{ 0x2C0819F0,0xFFC6,0x4F89,{ 0xA0,0x6F,0x18,0xFA,0x10,0x79,0x29,0x33 } }; // 2C0819F0-FFC6-4F89-A06F-18FA10792933
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IOrientationSensor>{ 0x5E354635,0xCF6B,0x4C63,{ 0xAB,0xD8,0x10,0x25,0x2B,0x0B,0xF6,0xEC } }; // 5E354635-CF6B-4C63-ABD8-10252B0BF6EC
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IOrientationSensor2>{ 0x0D924CF9,0x2F1F,0x49C9,{ 0x80,0x42,0x4A,0x18,0x13,0xD6,0x77,0x60 } }; // 0D924CF9-2F1F-49C9-8042-4A1813D67760
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IOrientationSensor3>{ 0x2CCE578D,0x646B,0x48C5,{ 0xB7,0xEE,0x44,0xFD,0xC4,0xC6,0xAA,0xFD } }; // 2CCE578D-646B-48C5-B7EE-44FDC4C6AAFD
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IOrientationSensorDeviceId>{ 0x5A69B648,0x4C29,0x49EC,{ 0xB2,0x8F,0xEA,0x1D,0x11,0x7B,0x66,0xF0 } }; // 5A69B648-4C29-49EC-B28F-EA1D117B66F0
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IOrientationSensorReading>{ 0x4756C993,0x6595,0x4897,{ 0xBC,0xC6,0xD5,0x37,0xEE,0x75,0x75,0x64 } }; // 4756C993-6595-4897-BCC6-D537EE757564
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IOrientationSensorReading2>{ 0x00576E5F,0x49F8,0x4C05,{ 0x9E,0x07,0x24,0xFA,0xC7,0x94,0x08,0xC3 } }; // 00576E5F-49F8-4C05-9E07-24FAC79408C3
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs>{ 0x012C1186,0xC3BA,0x46BC,{ 0xAE,0x65,0x7A,0x98,0x99,0x6C,0xBF,0xB8 } }; // 012C1186-C3BA-46BC-AE65-7A98996CBFB8
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy>{ 0xD1AC9824,0x3F5A,0x49A2,{ 0xBC,0x7B,0x11,0x80,0xBC,0x38,0xCD,0x2B } }; // D1AC9824-3F5A-49A2-BC7B-1180BC38CD2B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IOrientationSensorStatics>{ 0x10EF8712,0xFB4C,0x428A,{ 0x89,0x8B,0x27,0x65,0xE4,0x09,0xE6,0x69 } }; // 10EF8712-FB4C-428A-898B-2765E409E669
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IOrientationSensorStatics2>{ 0x59DA0D0B,0xD40A,0x4C71,{ 0x92,0x76,0x8A,0x27,0x2A,0x0A,0x66,0x19 } }; // 59DA0D0B-D40A-4C71-9276-8A272A0A6619
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IOrientationSensorStatics3>{ 0xD82CE920,0x2777,0x40FF,{ 0x9F,0x59,0xD6,0x54,0xB0,0x85,0xF1,0x2F } }; // D82CE920-2777-40FF-9F59-D654B085F12F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IOrientationSensorStatics4>{ 0xA67FEB55,0x2C85,0x4B28,{ 0xA0,0xFE,0x58,0xC4,0xB2,0x04,0x95,0xF5 } }; // A67FEB55-2C85-4B28-A0FE-58C4B20495F5
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IPedometer>{ 0x9A1E013D,0x3D98,0x45F8,{ 0x89,0x20,0x8E,0x4E,0xCA,0xCA,0x5F,0x97 } }; // 9A1E013D-3D98-45F8-8920-8E4ECACA5F97
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IPedometer2>{ 0xE5A406DF,0x2B81,0x4ADD,{ 0xB2,0xFF,0x77,0xAB,0x6C,0x98,0xBA,0x19 } }; // E5A406DF-2B81-4ADD-B2FF-77AB6C98BA19
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IPedometerDataThresholdFactory>{ 0xCBAD8F50,0x7A54,0x466B,{ 0x90,0x10,0x77,0xA1,0x62,0xFC,0xA5,0xD7 } }; // CBAD8F50-7A54-466B-9010-77A162FCA5D7
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IPedometerReading>{ 0x2245DCF4,0xA8E1,0x432F,{ 0x89,0x6A,0xBE,0x0D,0xD9,0xB0,0x2D,0x24 } }; // 2245DCF4-A8E1-432F-896A-BE0DD9B02D24
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IPedometerReadingChangedEventArgs>{ 0xF855E47E,0xABBC,0x4456,{ 0x86,0xA8,0x25,0xCF,0x2B,0x33,0x37,0x42 } }; // F855E47E-ABBC-4456-86A8-25CF2B333742
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IPedometerStatics>{ 0x82980A2F,0x4083,0x4DFB,{ 0xB4,0x11,0x93,0x8E,0xA0,0xF4,0xB9,0x46 } }; // 82980A2F-4083-4DFB-B411-938EA0F4B946
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IPedometerStatics2>{ 0x79F5C6BB,0xCE0E,0x4133,{ 0xB4,0x7E,0x86,0x27,0xEA,0x72,0xF6,0x77 } }; // 79F5C6BB-CE0E-4133-B47E-8627EA72F677
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IProximitySensor>{ 0x54C076B8,0xECFB,0x4944,{ 0xB9,0x28,0x74,0xFC,0x50,0x4D,0x47,0xEE } }; // 54C076B8-ECFB-4944-B928-74FC504D47EE
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IProximitySensorDataThresholdFactory>{ 0x905AC121,0x6D27,0x4AD3,{ 0x9D,0xB5,0x64,0x67,0xF2,0xA5,0xAD,0x9D } }; // 905AC121-6D27-4AD3-9DB5-6467F2A5AD9D
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IProximitySensorReading>{ 0x71228D59,0x132D,0x4D5F,{ 0x8F,0xF9,0x2F,0x0D,0xB8,0x75,0x1C,0xED } }; // 71228D59-132D-4D5F-8FF9-2F0DB8751CED
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs>{ 0xCFC2F366,0xC3E8,0x40FD,{ 0x8C,0xC3,0x67,0xE2,0x89,0x00,0x49,0x38 } }; // CFC2F366-C3E8-40FD-8CC3-67E289004938
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IProximitySensorStatics>{ 0x29186649,0x6269,0x4E57,{ 0xA5,0xAD,0x82,0xBE,0x80,0x81,0x33,0x92 } }; // 29186649-6269-4E57-A5AD-82BE80813392
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IProximitySensorStatics2>{ 0xCBF473AE,0xE9CA,0x422F,{ 0xAD,0x67,0x4C,0x3D,0x25,0xDF,0x35,0x0C } }; // CBF473AE-E9CA-422F-AD67-4C3D25DF350C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ISensorDataThreshold>{ 0x54DAEC61,0xFE4B,0x4E07,{ 0xB2,0x60,0x3A,0x4C,0xDF,0xBE,0x39,0x6E } }; // 54DAEC61-FE4B-4E07-B260-3A4CDFBE396E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails>{ 0x9106F1B7,0xE88D,0x48B1,{ 0xBC,0x90,0x61,0x9C,0x7B,0x34,0x93,0x91 } }; // 9106F1B7-E88D-48B1-BC90-619C7B349391
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ISensorQuaternion>{ 0xC9C5C827,0xC71C,0x46E7,{ 0x9D,0xA3,0x36,0xA1,0x93,0xB2,0x32,0xBC } }; // C9C5C827-C71C-46E7-9DA3-36A193B232BC
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ISensorRotationMatrix>{ 0x0A3D5A67,0x22F4,0x4392,{ 0x95,0x38,0x65,0xD0,0xBD,0x06,0x4A,0xA6 } }; // 0A3D5A67-22F4-4392-9538-65D0BD064AA6
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor>{ 0x5FF53856,0x214A,0x4DEE,{ 0xA3,0xF9,0x61,0x6F,0x1A,0xB0,0x6F,0xFD } }; // 5FF53856-214A-4DEE-A3F9-616F1AB06FFD
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor2>{ 0xA277A798,0x8870,0x453E,{ 0x8B,0xD6,0xB8,0xF5,0xD8,0xD7,0x94,0x1B } }; // A277A798-8870-453E-8BD6-B8F5D8D7941B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId>{ 0xFBC00ACB,0x3B76,0x41F6,{ 0x80,0x91,0x30,0xEF,0xE6,0x46,0xD3,0xCF } }; // FBC00ACB-3B76-41F6-8091-30EFE646D3CF
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs>{ 0xBCD5C660,0x23D4,0x4B4C,{ 0xA2,0x2E,0xBA,0x81,0xAD,0xE0,0xC6,0x01 } }; // BCD5C660-23D4-4B4C-A22E-BA81ADE0C601
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics>{ 0x72ED066F,0x70AA,0x40C6,{ 0x9B,0x1B,0x34,0x33,0xF7,0x45,0x9B,0x4E } }; // 72ED066F-70AA-40C6-9B1B-3433F7459B4E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics2>{ 0x848F9C7F,0xB138,0x4E11,{ 0x89,0x10,0xA2,0xA2,0xA3,0xB5,0x6D,0x83 } }; // 848F9C7F-B138-4E11-8910-A2A2A3B56D83
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::IWakeOnApproachOptions>{ 0xF0B87AE7,0x7E1F,0x5EA5,{ 0x81,0x4D,0x6B,0x7E,0x07,0xDE,0xFC,0x2B } }; // F0B87AE7-7E1F-5EA5-814D-6B7E07DEFC2B
    template <> struct default_interface<winrt::Windows::Devices::Sensors::Accelerometer>{ using type = winrt::Windows::Devices::Sensors::IAccelerometer; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::AccelerometerDataThreshold>{ using type = winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::AccelerometerReading>{ using type = winrt::Windows::Devices::Sensors::IAccelerometerReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::AccelerometerShakenEventArgs>{ using type = winrt::Windows::Devices::Sensors::IAccelerometerShakenEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::ActivitySensor>{ using type = winrt::Windows::Devices::Sensors::IActivitySensor; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::ActivitySensorReading>{ using type = winrt::Windows::Devices::Sensors::IActivitySensorReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangeReport>{ using type = winrt::Windows::Devices::Sensors::IActivitySensorReadingChangeReport; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::ActivitySensorTriggerDetails>{ using type = winrt::Windows::Devices::Sensors::IActivitySensorTriggerDetails; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::AdaptiveDimmingOptions>{ using type = winrt::Windows::Devices::Sensors::IAdaptiveDimmingOptions; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::Altimeter>{ using type = winrt::Windows::Devices::Sensors::IAltimeter; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::AltimeterReading>{ using type = winrt::Windows::Devices::Sensors::IAltimeterReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::AltimeterReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::Barometer>{ using type = winrt::Windows::Devices::Sensors::IBarometer; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::BarometerDataThreshold>{ using type = winrt::Windows::Devices::Sensors::IBarometerDataThreshold; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::BarometerReading>{ using type = winrt::Windows::Devices::Sensors::IBarometerReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::BarometerReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::IBarometerReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::Compass>{ using type = winrt::Windows::Devices::Sensors::ICompass; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::CompassDataThreshold>{ using type = winrt::Windows::Devices::Sensors::ICompassDataThreshold; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::CompassReading>{ using type = winrt::Windows::Devices::Sensors::ICompassReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::CompassReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::ICompassReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::Gyrometer>{ using type = winrt::Windows::Devices::Sensors::IGyrometer; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::GyrometerDataThreshold>{ using type = winrt::Windows::Devices::Sensors::IGyrometerDataThreshold; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::GyrometerReading>{ using type = winrt::Windows::Devices::Sensors::IGyrometerReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::GyrometerReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::HingeAngleReading>{ using type = winrt::Windows::Devices::Sensors::IHingeAngleReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::HingeAngleSensor>{ using type = winrt::Windows::Devices::Sensors::IHingeAngleSensor; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::HumanPresenceFeatures>{ using type = winrt::Windows::Devices::Sensors::IHumanPresenceFeatures; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::HumanPresenceSensor>{ using type = winrt::Windows::Devices::Sensors::IHumanPresenceSensor; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::HumanPresenceSensorReading>{ using type = winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingUpdate>{ using type = winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::HumanPresenceSettings>{ using type = winrt::Windows::Devices::Sensors::IHumanPresenceSettings; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::Inclinometer>{ using type = winrt::Windows::Devices::Sensors::IInclinometer; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::InclinometerDataThreshold>{ using type = winrt::Windows::Devices::Sensors::IInclinometerDataThreshold; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::InclinometerReading>{ using type = winrt::Windows::Devices::Sensors::IInclinometerReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::InclinometerReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::LightSensor>{ using type = winrt::Windows::Devices::Sensors::ILightSensor; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::LightSensorDataThreshold>{ using type = winrt::Windows::Devices::Sensors::ILightSensorDataThreshold; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::LightSensorReading>{ using type = winrt::Windows::Devices::Sensors::ILightSensorReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::LightSensorReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::LockOnLeaveOptions>{ using type = winrt::Windows::Devices::Sensors::ILockOnLeaveOptions; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::Magnetometer>{ using type = winrt::Windows::Devices::Sensors::IMagnetometer; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::MagnetometerDataThreshold>{ using type = winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::MagnetometerReading>{ using type = winrt::Windows::Devices::Sensors::IMagnetometerReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::OrientationSensor>{ using type = winrt::Windows::Devices::Sensors::IOrientationSensor; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::OrientationSensorReading>{ using type = winrt::Windows::Devices::Sensors::IOrientationSensorReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::Pedometer>{ using type = winrt::Windows::Devices::Sensors::IPedometer; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::PedometerDataThreshold>{ using type = winrt::Windows::Devices::Sensors::ISensorDataThreshold; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::PedometerReading>{ using type = winrt::Windows::Devices::Sensors::IPedometerReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::PedometerReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::IPedometerReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::ProximitySensor>{ using type = winrt::Windows::Devices::Sensors::IProximitySensor; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::ProximitySensorDataThreshold>{ using type = winrt::Windows::Devices::Sensors::ISensorDataThreshold; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::ProximitySensorDisplayOnOffController>{ using type = winrt::Windows::Foundation::IClosable; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::ProximitySensorReading>{ using type = winrt::Windows::Devices::Sensors::IProximitySensorReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails>{ using type = winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::SensorQuaternion>{ using type = winrt::Windows::Devices::Sensors::ISensorQuaternion; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::SensorRotationMatrix>{ using type = winrt::Windows::Devices::Sensors::ISensorRotationMatrix; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::SimpleOrientationSensor>{ using type = winrt::Windows::Devices::Sensors::ISimpleOrientationSensor; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::WakeOnApproachOptions>{ using type = winrt::Windows::Devices::Sensors::IWakeOnApproachOptions; };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReading(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinimumReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ReportInterval(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Shaken(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Shaken(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometer2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReadingTransform(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReadingTransform(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometer3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReportLatency(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportLatency(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxBatchSize(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometer4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ReadingType(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometer5>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ReportThreshold(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_XAxisInGForce(double*) noexcept = 0;
            virtual int32_t __stdcall put_XAxisInGForce(double) noexcept = 0;
            virtual int32_t __stdcall get_YAxisInGForce(double*) noexcept = 0;
            virtual int32_t __stdcall put_YAxisInGForce(double) noexcept = 0;
            virtual int32_t __stdcall get_ZAxisInGForce(double*) noexcept = 0;
            virtual int32_t __stdcall put_ZAxisInGForce(double) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometerDeviceId>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometerReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_AccelerationX(double*) noexcept = 0;
            virtual int32_t __stdcall get_AccelerationY(double*) noexcept = 0;
            virtual int32_t __stdcall get_AccelerationZ(double*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometerReading2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PerformanceCount(void**) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometerShakenEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefaultWithAccelerometerReadingType(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAccelerometerStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IActivitySensor>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReadingAsync(void**) noexcept = 0;
            virtual int32_t __stdcall get_SubscribedActivities(void**) noexcept = 0;
            virtual int32_t __stdcall get_PowerInMilliwatts(double*) noexcept = 0;
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportedActivities(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinimumReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IActivitySensorReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Activity(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Confidence(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangeReport>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IActivitySensorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefaultAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetSystemHistoryAsync(int64_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetSystemHistoryWithDurationAsync(int64_t, int64_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IActivitySensorTriggerDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ReadReports(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAdaptiveDimmingOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AllowWhenExternalDisplayConnected(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowWhenExternalDisplayConnected(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAltimeter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReading(void**) noexcept = 0;
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinimumReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ReportInterval(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAltimeter2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReportLatency(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportLatency(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxBatchSize(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAltimeterReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_AltitudeChangeInMeters(double*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAltimeterReading2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PerformanceCount(void**) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IAltimeterStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IBarometer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReading(void**) noexcept = 0;
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinimumReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ReportInterval(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IBarometer2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReportLatency(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportLatency(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxBatchSize(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IBarometer3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ReportThreshold(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IBarometerDataThreshold>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Hectopascals(double*) noexcept = 0;
            virtual int32_t __stdcall put_Hectopascals(double) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IBarometerReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_StationPressureInHectopascals(double*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IBarometerReading2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PerformanceCount(void**) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IBarometerReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IBarometerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IBarometerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ICompass>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReading(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinimumReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ReportInterval(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ICompass2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReadingTransform(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReadingTransform(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ICompass3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReportLatency(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportLatency(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxBatchSize(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ICompass4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ReportThreshold(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ICompassDataThreshold>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Degrees(double*) noexcept = 0;
            virtual int32_t __stdcall put_Degrees(double) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ICompassDeviceId>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ICompassReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_HeadingMagneticNorth(double*) noexcept = 0;
            virtual int32_t __stdcall get_HeadingTrueNorth(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ICompassReading2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PerformanceCount(void**) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ICompassReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ICompassReadingHeadingAccuracy>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_HeadingAccuracy(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ICompassStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ICompassStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IGyrometer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReading(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinimumReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ReportInterval(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IGyrometer2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReadingTransform(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReadingTransform(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IGyrometer3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReportLatency(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportLatency(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxBatchSize(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IGyrometer4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ReportThreshold(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IGyrometerDataThreshold>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_XAxisInDegreesPerSecond(double*) noexcept = 0;
            virtual int32_t __stdcall put_XAxisInDegreesPerSecond(double) noexcept = 0;
            virtual int32_t __stdcall get_YAxisInDegreesPerSecond(double*) noexcept = 0;
            virtual int32_t __stdcall put_YAxisInDegreesPerSecond(double) noexcept = 0;
            virtual int32_t __stdcall get_ZAxisInDegreesPerSecond(double*) noexcept = 0;
            virtual int32_t __stdcall put_ZAxisInDegreesPerSecond(double) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IGyrometerDeviceId>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IGyrometerReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_AngularVelocityX(double*) noexcept = 0;
            virtual int32_t __stdcall get_AngularVelocityY(double*) noexcept = 0;
            virtual int32_t __stdcall get_AngularVelocityZ(double*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IGyrometerReading2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PerformanceCount(void**) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IGyrometerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IGyrometerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHingeAngleReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_AngleInDegrees(double*) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHingeAngleSensor>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReadingAsync(void**) noexcept = 0;
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinReportThresholdInDegrees(double*) noexcept = 0;
            virtual int32_t __stdcall get_ReportThresholdInDegrees(double*) noexcept = 0;
            virtual int32_t __stdcall put_ReportThresholdInDegrees(double) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall GetDefaultAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetRelatedToAdjacentPanelsAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceFeatures>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SensorId(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportedWakeOrLockDistancesInMillimeters(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsWakeOnApproachSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsLockOnLeaveSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsAttentionAwareDimmingSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceFeatures2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsAdaptiveDimmingSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceSensor>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_MaxDetectableDistanceInMillimeters(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinDetectableDistanceInMillimeters(void**) noexcept = 0;
            virtual int32_t __stdcall GetCurrentReading(void**) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceSensor2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsPresenceSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsEngagementSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Initialize(void*) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
            virtual int32_t __stdcall ProcessReading(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ProcessReadingTimeoutExpired(void*) noexcept = 0;
            virtual int32_t __stdcall Stop() noexcept = 0;
            virtual int32_t __stdcall Uninitialize() noexcept = 0;
            virtual int32_t __stdcall Reset() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Presence(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Engagement(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DistanceInMillimeters(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(void**) noexcept = 0;
            virtual int32_t __stdcall put_Timestamp(void*) noexcept = 0;
            virtual int32_t __stdcall get_Presence(void**) noexcept = 0;
            virtual int32_t __stdcall put_Presence(void*) noexcept = 0;
            virtual int32_t __stdcall get_Engagement(void**) noexcept = 0;
            virtual int32_t __stdcall put_Engagement(void*) noexcept = 0;
            virtual int32_t __stdcall get_DistanceInMillimeters(void**) noexcept = 0;
            virtual int32_t __stdcall put_DistanceInMillimeters(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDefaultAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromId(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceSettings>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SensorId(void**) noexcept = 0;
            virtual int32_t __stdcall put_SensorId(void*) noexcept = 0;
            virtual int32_t __stdcall get_IsWakeOnApproachEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsWakeOnApproachEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_WakeOnApproachDistanceInMillimeters(void**) noexcept = 0;
            virtual int32_t __stdcall put_WakeOnApproachDistanceInMillimeters(void*) noexcept = 0;
            virtual int32_t __stdcall get_IsLockOnLeaveEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsLockOnLeaveEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_LockOnLeaveDistanceInMillimeters(void**) noexcept = 0;
            virtual int32_t __stdcall put_LockOnLeaveDistanceInMillimeters(void*) noexcept = 0;
            virtual int32_t __stdcall get_LockOnLeaveTimeout(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_LockOnLeaveTimeout(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_IsAttentionAwareDimmingEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsAttentionAwareDimmingEnabled(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceSettings2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsAdaptiveDimmingEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsAdaptiveDimmingEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_WakeOptions(void**) noexcept = 0;
            virtual int32_t __stdcall get_DimmingOptions(void**) noexcept = 0;
            virtual int32_t __stdcall get_LockOptions(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentSettingsAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetCurrentSettings(void**) noexcept = 0;
            virtual int32_t __stdcall UpdateSettingsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall UpdateSettings(void*) noexcept = 0;
            virtual int32_t __stdcall GetSupportedFeaturesForSensorIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetSupportedFeaturesForSensorId(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetSupportedLockOnLeaveTimeouts(void**) noexcept = 0;
            virtual int32_t __stdcall add_SettingsChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SettingsChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReading(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinimumReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ReportInterval(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometer2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReadingTransform(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReadingTransform(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ReadingType(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometer3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReportLatency(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportLatency(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxBatchSize(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometer4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ReportThreshold(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometerDataThreshold>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PitchInDegrees(float*) noexcept = 0;
            virtual int32_t __stdcall put_PitchInDegrees(float) noexcept = 0;
            virtual int32_t __stdcall get_RollInDegrees(float*) noexcept = 0;
            virtual int32_t __stdcall put_RollInDegrees(float) noexcept = 0;
            virtual int32_t __stdcall get_YawInDegrees(float*) noexcept = 0;
            virtual int32_t __stdcall put_YawInDegrees(float) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometerDeviceId>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometerReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_PitchDegrees(float*) noexcept = 0;
            virtual int32_t __stdcall get_RollDegrees(float*) noexcept = 0;
            virtual int32_t __stdcall get_YawDegrees(float*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometerReading2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PerformanceCount(void**) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometerReadingYawAccuracy>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_YawAccuracy(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefaultForRelativeReadings(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometerStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefaultWithSensorReadingType(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IInclinometerStatics4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ILightSensor>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReading(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinimumReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ReportInterval(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ILightSensor2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReportLatency(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportLatency(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxBatchSize(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ILightSensor3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ReportThreshold(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ILightSensorDataThreshold>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_LuxPercentage(float*) noexcept = 0;
            virtual int32_t __stdcall put_LuxPercentage(float) noexcept = 0;
            virtual int32_t __stdcall get_AbsoluteLux(float*) noexcept = 0;
            virtual int32_t __stdcall put_AbsoluteLux(float) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ILightSensorDeviceId>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ILightSensorReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_IlluminanceInLux(float*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ILightSensorReading2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PerformanceCount(void**) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ILightSensorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ILightSensorStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ILockOnLeaveOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AllowWhenExternalDisplayConnected(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowWhenExternalDisplayConnected(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IMagnetometer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReading(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinimumReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ReportInterval(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IMagnetometer2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReadingTransform(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReadingTransform(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IMagnetometer3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReportLatency(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportLatency(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxBatchSize(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IMagnetometer4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ReportThreshold(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_XAxisMicroteslas(float*) noexcept = 0;
            virtual int32_t __stdcall put_XAxisMicroteslas(float) noexcept = 0;
            virtual int32_t __stdcall get_YAxisMicroteslas(float*) noexcept = 0;
            virtual int32_t __stdcall put_YAxisMicroteslas(float) noexcept = 0;
            virtual int32_t __stdcall get_ZAxisMicroteslas(float*) noexcept = 0;
            virtual int32_t __stdcall put_ZAxisMicroteslas(float) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IMagnetometerDeviceId>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IMagnetometerReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_MagneticFieldX(float*) noexcept = 0;
            virtual int32_t __stdcall get_MagneticFieldY(float*) noexcept = 0;
            virtual int32_t __stdcall get_MagneticFieldZ(float*) noexcept = 0;
            virtual int32_t __stdcall get_DirectionalAccuracy(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IMagnetometerReading2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PerformanceCount(void**) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IMagnetometerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IMagnetometerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IOrientationSensor>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReading(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinimumReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ReportInterval(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IOrientationSensor2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReadingTransform(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReadingTransform(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ReadingType(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IOrientationSensor3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReportLatency(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportLatency(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxBatchSize(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IOrientationSensorDeviceId>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IOrientationSensorReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_RotationMatrix(void**) noexcept = 0;
            virtual int32_t __stdcall get_Quaternion(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IOrientationSensorReading2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PerformanceCount(void**) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_YawAccuracy(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IOrientationSensorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IOrientationSensorStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefaultForRelativeReadings(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IOrientationSensorStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefaultWithSensorReadingType(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDefaultWithSensorReadingTypeAndSensorOptimizationGoal(int32_t, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IOrientationSensorStatics4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorWithSensorReadingTypeAndSensorOptimizationGoal(int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IPedometer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_PowerInMilliwatts(double*) noexcept = 0;
            virtual int32_t __stdcall get_MinimumReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ReportInterval(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IPedometer2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReadings(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IPedometerDataThresholdFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IPedometerReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_StepKind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CumulativeSteps(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_CumulativeStepsDuration(int64_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IPedometerReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IPedometerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDefaultAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall GetSystemHistoryAsync(int64_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetSystemHistoryWithDurationAsync(int64_t, int64_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IPedometerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetReadingsFromTriggerDetails(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IProximitySensor>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_MaxDistanceInMillimeters(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinDistanceInMillimeters(void**) noexcept = 0;
            virtual int32_t __stdcall GetCurrentReading(void**) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall CreateDisplayOnOffController(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IProximitySensorDataThresholdFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IProximitySensorReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsDetected(bool*) noexcept = 0;
            virtual int32_t __stdcall get_DistanceInMillimeters(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IProximitySensorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall FromId(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IProximitySensorStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetReadingsFromTriggerDetails(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ISensorDataThreshold>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_SensorType(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ISensorQuaternion>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_W(float*) noexcept = 0;
            virtual int32_t __stdcall get_X(float*) noexcept = 0;
            virtual int32_t __stdcall get_Y(float*) noexcept = 0;
            virtual int32_t __stdcall get_Z(float*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ISensorRotationMatrix>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_M11(float*) noexcept = 0;
            virtual int32_t __stdcall get_M12(float*) noexcept = 0;
            virtual int32_t __stdcall get_M13(float*) noexcept = 0;
            virtual int32_t __stdcall get_M21(float*) noexcept = 0;
            virtual int32_t __stdcall get_M22(float*) noexcept = 0;
            virtual int32_t __stdcall get_M23(float*) noexcept = 0;
            virtual int32_t __stdcall get_M31(float*) noexcept = 0;
            virtual int32_t __stdcall get_M32(float*) noexcept = 0;
            virtual int32_t __stdcall get_M33(float*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentOrientation(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_OrientationChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_OrientationChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReadingTransform(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReadingTransform(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Orientation(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::IWakeOnApproachOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AllowWhenExternalDisplayConnected(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowWhenExternalDisplayConnected(bool) noexcept = 0;
            virtual int32_t __stdcall get_DisableWhenBatterySaverOn(bool*) noexcept = 0;
            virtual int32_t __stdcall put_DisableWhenBatterySaverOn(bool) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometer
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AccelerometerReading) GetCurrentReading() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MinimumReportInterval() const;
        WINRT_IMPL_AUTO(void) ReportInterval(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportInterval() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Accelerometer, winrt::Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IAccelerometer, &impl::abi_t<winrt::Windows::Devices::Sensors::IAccelerometer>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Accelerometer, winrt::Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Shaken(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Accelerometer, winrt::Windows::Devices::Sensors::AccelerometerShakenEventArgs> const& handler) const;
        using Shaken_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IAccelerometer, &impl::abi_t<winrt::Windows::Devices::Sensors::IAccelerometer>::remove_Shaken>;
        [[nodiscard]] Shaken_revoker Shaken(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Accelerometer, winrt::Windows::Devices::Sensors::AccelerometerShakenEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Shaken(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometer>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometer<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometer2
    {
        WINRT_IMPL_AUTO(void) ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) ReadingTransform() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometer2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometer2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometer3
    {
        WINRT_IMPL_AUTO(void) ReportLatency(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportLatency() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxBatchSize() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometer3>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometer3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometer4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AccelerometerReadingType) ReadingType() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometer4>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometer4<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometer5
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AccelerometerDataThreshold) ReportThreshold() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometer5>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometer5<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometerDataThreshold
    {
        [[nodiscard]] WINRT_IMPL_AUTO(double) XAxisInGForce() const;
        WINRT_IMPL_AUTO(void) XAxisInGForce(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) YAxisInGForce() const;
        WINRT_IMPL_AUTO(void) YAxisInGForce(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) ZAxisInGForce() const;
        WINRT_IMPL_AUTO(void) ZAxisInGForce(double value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometerDataThreshold<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometerDeviceId
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometerDeviceId>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometerDeviceId<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometerReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) AccelerationX() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) AccelerationY() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) AccelerationZ() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometerReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometerReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometerReading2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) PerformanceCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometerReading2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometerReading2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometerReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AccelerometerReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometerReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometerShakenEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometerShakenEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometerShakenEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Accelerometer) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometerStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometerStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Accelerometer) GetDefault(winrt::Windows::Devices::Sensors::AccelerometerReadingType const& readingType) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometerStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAccelerometerStatics3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Accelerometer>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(winrt::Windows::Devices::Sensors::AccelerometerReadingType const& readingType) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAccelerometerStatics3>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAccelerometerStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IActivitySensor
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensorReading>) GetCurrentReadingAsync() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Sensors::ActivityType>) SubscribedActivities() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) PowerInMilliwatts() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivityType>) SupportedActivities() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MinimumReportInterval() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::ActivitySensor, winrt::Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IActivitySensor, &impl::abi_t<winrt::Windows::Devices::Sensors::IActivitySensor>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::ActivitySensor, winrt::Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IActivitySensor>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IActivitySensor<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IActivitySensorReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ActivityType) Activity() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ActivitySensorReadingConfidence) Confidence() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IActivitySensorReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IActivitySensorReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IActivitySensorReadingChangeReport
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ActivitySensorReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangeReport>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IActivitySensorReadingChangeReport<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IActivitySensorReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ActivitySensorReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IActivitySensorReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IActivitySensorStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensor>) GetDefaultAsync() const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensor>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivitySensorReading>>) GetSystemHistoryAsync(winrt::Windows::Foundation::DateTime const& fromTime) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivitySensorReading>>) GetSystemHistoryAsync(winrt::Windows::Foundation::DateTime const& fromTime, winrt::Windows::Foundation::TimeSpan const& duration) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IActivitySensorStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IActivitySensorStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IActivitySensorTriggerDetails
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangeReport>) ReadReports() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IActivitySensorTriggerDetails>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IActivitySensorTriggerDetails<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAdaptiveDimmingOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowWhenExternalDisplayConnected() const;
        WINRT_IMPL_AUTO(void) AllowWhenExternalDisplayConnected(bool value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAdaptiveDimmingOptions>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAdaptiveDimmingOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAltimeter
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AltimeterReading) GetCurrentReading() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MinimumReportInterval() const;
        WINRT_IMPL_AUTO(void) ReportInterval(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportInterval() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Altimeter, winrt::Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IAltimeter, &impl::abi_t<winrt::Windows::Devices::Sensors::IAltimeter>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Altimeter, winrt::Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAltimeter>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAltimeter<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAltimeter2
    {
        WINRT_IMPL_AUTO(void) ReportLatency(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportLatency() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxBatchSize() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAltimeter2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAltimeter2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAltimeterReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) AltitudeChangeInMeters() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAltimeterReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAltimeterReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAltimeterReading2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) PerformanceCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAltimeterReading2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAltimeterReading2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAltimeterReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AltimeterReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAltimeterReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IAltimeterStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Altimeter) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IAltimeterStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IAltimeterStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IBarometer
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::BarometerReading) GetCurrentReading() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MinimumReportInterval() const;
        WINRT_IMPL_AUTO(void) ReportInterval(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportInterval() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Barometer, winrt::Windows::Devices::Sensors::BarometerReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IBarometer, &impl::abi_t<winrt::Windows::Devices::Sensors::IBarometer>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Barometer, winrt::Windows::Devices::Sensors::BarometerReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IBarometer>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IBarometer<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IBarometer2
    {
        WINRT_IMPL_AUTO(void) ReportLatency(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportLatency() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxBatchSize() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IBarometer2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IBarometer2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IBarometer3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::BarometerDataThreshold) ReportThreshold() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IBarometer3>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IBarometer3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IBarometerDataThreshold
    {
        [[nodiscard]] WINRT_IMPL_AUTO(double) Hectopascals() const;
        WINRT_IMPL_AUTO(void) Hectopascals(double value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IBarometerDataThreshold>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IBarometerDataThreshold<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IBarometerReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) StationPressureInHectopascals() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IBarometerReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IBarometerReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IBarometerReading2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) PerformanceCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IBarometerReading2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IBarometerReading2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IBarometerReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::BarometerReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IBarometerReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IBarometerReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IBarometerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Barometer) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IBarometerStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IBarometerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IBarometerStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Barometer>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IBarometerStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IBarometerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ICompass
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::CompassReading) GetCurrentReading() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MinimumReportInterval() const;
        WINRT_IMPL_AUTO(void) ReportInterval(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportInterval() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Compass, winrt::Windows::Devices::Sensors::CompassReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::ICompass, &impl::abi_t<winrt::Windows::Devices::Sensors::ICompass>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Compass, winrt::Windows::Devices::Sensors::CompassReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ICompass>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ICompass<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ICompass2
    {
        WINRT_IMPL_AUTO(void) ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) ReadingTransform() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ICompass2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ICompass2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ICompass3
    {
        WINRT_IMPL_AUTO(void) ReportLatency(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportLatency() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxBatchSize() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ICompass3>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ICompass3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ICompass4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::CompassDataThreshold) ReportThreshold() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ICompass4>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ICompass4<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ICompassDataThreshold
    {
        [[nodiscard]] WINRT_IMPL_AUTO(double) Degrees() const;
        WINRT_IMPL_AUTO(void) Degrees(double value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ICompassDataThreshold>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ICompassDataThreshold<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ICompassDeviceId
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ICompassDeviceId>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ICompassDeviceId<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ICompassReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) HeadingMagneticNorth() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) HeadingTrueNorth() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ICompassReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ICompassReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ICompassReading2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) PerformanceCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ICompassReading2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ICompassReading2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ICompassReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::CompassReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ICompassReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ICompassReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ICompassReadingHeadingAccuracy
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerAccuracy) HeadingAccuracy() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ICompassReadingHeadingAccuracy>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ICompassReadingHeadingAccuracy<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ICompassStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Compass) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ICompassStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ICompassStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ICompassStatics2
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Compass>) FromIdAsync(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ICompassStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ICompassStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IGyrometer
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::GyrometerReading) GetCurrentReading() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MinimumReportInterval() const;
        WINRT_IMPL_AUTO(void) ReportInterval(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportInterval() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Gyrometer, winrt::Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IGyrometer, &impl::abi_t<winrt::Windows::Devices::Sensors::IGyrometer>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Gyrometer, winrt::Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IGyrometer>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IGyrometer<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IGyrometer2
    {
        WINRT_IMPL_AUTO(void) ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) ReadingTransform() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IGyrometer2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IGyrometer2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IGyrometer3
    {
        WINRT_IMPL_AUTO(void) ReportLatency(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportLatency() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxBatchSize() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IGyrometer3>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IGyrometer3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IGyrometer4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::GyrometerDataThreshold) ReportThreshold() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IGyrometer4>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IGyrometer4<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IGyrometerDataThreshold
    {
        [[nodiscard]] WINRT_IMPL_AUTO(double) XAxisInDegreesPerSecond() const;
        WINRT_IMPL_AUTO(void) XAxisInDegreesPerSecond(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) YAxisInDegreesPerSecond() const;
        WINRT_IMPL_AUTO(void) YAxisInDegreesPerSecond(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) ZAxisInDegreesPerSecond() const;
        WINRT_IMPL_AUTO(void) ZAxisInDegreesPerSecond(double value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IGyrometerDataThreshold>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IGyrometerDataThreshold<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IGyrometerDeviceId
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IGyrometerDeviceId>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IGyrometerDeviceId<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IGyrometerReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) AngularVelocityX() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) AngularVelocityY() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) AngularVelocityZ() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IGyrometerReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IGyrometerReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IGyrometerReading2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) PerformanceCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IGyrometerReading2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IGyrometerReading2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IGyrometerReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::GyrometerReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IGyrometerReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IGyrometerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Gyrometer) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IGyrometerStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IGyrometerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IGyrometerStatics2
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Gyrometer>) FromIdAsync(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IGyrometerStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IGyrometerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHingeAngleReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) AngleInDegrees() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHingeAngleReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHingeAngleReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHingeAngleSensor
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleReading>) GetCurrentReadingAsync() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) MinReportThresholdInDegrees() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) ReportThresholdInDegrees() const;
        WINRT_IMPL_AUTO(void) ReportThresholdInDegrees(double value) const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::HingeAngleSensor, winrt::Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IHingeAngleSensor, &impl::abi_t<winrt::Windows::Devices::Sensors::IHingeAngleSensor>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::HingeAngleSensor, winrt::Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHingeAngleSensor>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHingeAngleSensor<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHingeAngleSensorReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HingeAngleReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHingeAngleSensorReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHingeAngleSensorStatics
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>) GetDefaultAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>) GetRelatedToAdjacentPanelsAsync(param::hstring const& firstPanelId, param::hstring const& secondPanelId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>) FromIdAsync(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHingeAngleSensorStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceFeatures
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SensorId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<uint32_t>) SupportedWakeOrLockDistancesInMillimeters() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsWakeOnApproachSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsLockOnLeaveSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAttentionAwareDimmingSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceFeatures>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceFeatures<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceFeatures2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAdaptiveDimmingSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceFeatures2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceFeatures2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceSensor
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) MaxDetectableDistanceInMillimeters() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) MinDetectableDistanceInMillimeters() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceSensorReading) GetCurrentReading() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::HumanPresenceSensor, winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IHumanPresenceSensor, &impl::abi_t<winrt::Windows::Devices::Sensors::IHumanPresenceSensor>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::HumanPresenceSensor, winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceSensor>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceSensor<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceSensor2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsPresenceSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsEngagementSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceSensor2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceSensor2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceSensorExtension
    {
        WINRT_IMPL_AUTO(void) Initialize(param::hstring const& deviceInterface) const;
        WINRT_IMPL_AUTO(void) Start() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingUpdate) ProcessReading(winrt::Windows::Devices::Sensors::HumanPresenceSensorReading const& reading) const;
        WINRT_IMPL_AUTO(void) ProcessReadingTimeoutExpired(winrt::Windows::Devices::Sensors::HumanPresenceSensorReading const& reading) const;
        WINRT_IMPL_AUTO(void) Stop() const;
        WINRT_IMPL_AUTO(void) Uninitialize() const;
        WINRT_IMPL_AUTO(void) Reset() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceSensorExtension<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceSensorReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresence) Presence() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanEngagement) Engagement() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) DistanceInMillimeters() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceSensorReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceSensorReading2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceSensorReading2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceSensorReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingUpdate
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) Timestamp() const;
        WINRT_IMPL_AUTO(void) Timestamp(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanPresence>) Presence() const;
        WINRT_IMPL_AUTO(void) Presence(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanPresence> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanEngagement>) Engagement() const;
        WINRT_IMPL_AUTO(void) Engagement(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanEngagement> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) DistanceInMillimeters() const;
        WINRT_IMPL_AUTO(void) DistanceInMillimeters(winrt::Windows::Foundation::IReference<uint32_t> const& value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingUpdate<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceSensorStatics
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSensor>) FromIdAsync(param::hstring const& sensorId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSensor>) GetDefaultAsync() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceSensorStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceSensorStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceSensor) FromId(param::hstring const& sensorId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceSensor) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceSensorStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceSettings
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SensorId() const;
        WINRT_IMPL_AUTO(void) SensorId(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsWakeOnApproachEnabled() const;
        WINRT_IMPL_AUTO(void) IsWakeOnApproachEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) WakeOnApproachDistanceInMillimeters() const;
        WINRT_IMPL_AUTO(void) WakeOnApproachDistanceInMillimeters(winrt::Windows::Foundation::IReference<uint32_t> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsLockOnLeaveEnabled() const;
        WINRT_IMPL_AUTO(void) IsLockOnLeaveEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) LockOnLeaveDistanceInMillimeters() const;
        WINRT_IMPL_AUTO(void) LockOnLeaveDistanceInMillimeters(winrt::Windows::Foundation::IReference<uint32_t> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) LockOnLeaveTimeout() const;
        WINRT_IMPL_AUTO(void) LockOnLeaveTimeout(winrt::Windows::Foundation::TimeSpan const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAttentionAwareDimmingEnabled() const;
        WINRT_IMPL_AUTO(void) IsAttentionAwareDimmingEnabled(bool value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceSettings>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceSettings2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAdaptiveDimmingEnabled() const;
        WINRT_IMPL_AUTO(void) IsAdaptiveDimmingEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::WakeOnApproachOptions) WakeOptions() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AdaptiveDimmingOptions) DimmingOptions() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::LockOnLeaveOptions) LockOptions() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceSettings2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceSettings2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSettings>) GetCurrentSettingsAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceSettings) GetCurrentSettings() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) UpdateSettingsAsync(winrt::Windows::Devices::Sensors::HumanPresenceSettings const& settings) const;
        WINRT_IMPL_AUTO(void) UpdateSettings(winrt::Windows::Devices::Sensors::HumanPresenceSettings const& settings) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceFeatures>) GetSupportedFeaturesForSensorIdAsync(param::hstring const& sensorId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceFeatures) GetSupportedFeaturesForSensorId(param::hstring const& sensorId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::TimeSpan>) GetSupportedLockOnLeaveTimeouts() const;
        WINRT_IMPL_AUTO(winrt::event_token) SettingsChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        using SettingsChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics, &impl::abi_t<winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics>::remove_SettingsChanged>;
        [[nodiscard]] SettingsChanged_revoker SettingsChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) SettingsChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometer
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::InclinometerReading) GetCurrentReading() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MinimumReportInterval() const;
        WINRT_IMPL_AUTO(void) ReportInterval(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportInterval() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Inclinometer, winrt::Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IInclinometer, &impl::abi_t<winrt::Windows::Devices::Sensors::IInclinometer>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Inclinometer, winrt::Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometer>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometer<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometer2
    {
        WINRT_IMPL_AUTO(void) ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) ReadingTransform() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SensorReadingType) ReadingType() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometer2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometer2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometer3
    {
        WINRT_IMPL_AUTO(void) ReportLatency(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportLatency() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxBatchSize() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometer3>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometer3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometer4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::InclinometerDataThreshold) ReportThreshold() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometer4>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometer4<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometerDataThreshold
    {
        [[nodiscard]] WINRT_IMPL_AUTO(float) PitchInDegrees() const;
        WINRT_IMPL_AUTO(void) PitchInDegrees(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) RollInDegrees() const;
        WINRT_IMPL_AUTO(void) RollInDegrees(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) YawInDegrees() const;
        WINRT_IMPL_AUTO(void) YawInDegrees(float value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometerDataThreshold>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometerDataThreshold<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometerDeviceId
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometerDeviceId>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometerDeviceId<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometerReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) PitchDegrees() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) RollDegrees() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) YawDegrees() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometerReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometerReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometerReading2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) PerformanceCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometerReading2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometerReading2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometerReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::InclinometerReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometerReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometerReadingYawAccuracy
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerAccuracy) YawAccuracy() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometerReadingYawAccuracy>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometerReadingYawAccuracy<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Inclinometer) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometerStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometerStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Inclinometer) GetDefaultForRelativeReadings() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometerStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometerStatics3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Inclinometer) GetDefault(winrt::Windows::Devices::Sensors::SensorReadingType const& sensorReadingtype) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometerStatics3>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometerStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IInclinometerStatics4
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(winrt::Windows::Devices::Sensors::SensorReadingType const& readingType) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Inclinometer>) FromIdAsync(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IInclinometerStatics4>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IInclinometerStatics4<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ILightSensor
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::LightSensorReading) GetCurrentReading() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MinimumReportInterval() const;
        WINRT_IMPL_AUTO(void) ReportInterval(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportInterval() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::LightSensor, winrt::Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::ILightSensor, &impl::abi_t<winrt::Windows::Devices::Sensors::ILightSensor>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::LightSensor, winrt::Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ILightSensor>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ILightSensor<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ILightSensor2
    {
        WINRT_IMPL_AUTO(void) ReportLatency(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportLatency() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxBatchSize() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ILightSensor2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ILightSensor2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ILightSensor3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::LightSensorDataThreshold) ReportThreshold() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ILightSensor3>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ILightSensor3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ILightSensorDataThreshold
    {
        [[nodiscard]] WINRT_IMPL_AUTO(float) LuxPercentage() const;
        WINRT_IMPL_AUTO(void) LuxPercentage(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) AbsoluteLux() const;
        WINRT_IMPL_AUTO(void) AbsoluteLux(float value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ILightSensorDataThreshold>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ILightSensorDataThreshold<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ILightSensorDeviceId
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ILightSensorDeviceId>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ILightSensorDeviceId<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ILightSensorReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) IlluminanceInLux() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ILightSensorReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ILightSensorReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ILightSensorReading2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) PerformanceCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ILightSensorReading2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ILightSensorReading2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ILightSensorReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::LightSensorReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ILightSensorReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ILightSensorStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::LightSensor) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ILightSensorStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ILightSensorStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ILightSensorStatics2
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::LightSensor>) FromIdAsync(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ILightSensorStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ILightSensorStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ILockOnLeaveOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowWhenExternalDisplayConnected() const;
        WINRT_IMPL_AUTO(void) AllowWhenExternalDisplayConnected(bool value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ILockOnLeaveOptions>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ILockOnLeaveOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IMagnetometer
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerReading) GetCurrentReading() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MinimumReportInterval() const;
        WINRT_IMPL_AUTO(void) ReportInterval(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportInterval() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Magnetometer, winrt::Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IMagnetometer, &impl::abi_t<winrt::Windows::Devices::Sensors::IMagnetometer>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Magnetometer, winrt::Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IMagnetometer>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IMagnetometer<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IMagnetometer2
    {
        WINRT_IMPL_AUTO(void) ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) ReadingTransform() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IMagnetometer2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IMagnetometer2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IMagnetometer3
    {
        WINRT_IMPL_AUTO(void) ReportLatency(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportLatency() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxBatchSize() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IMagnetometer3>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IMagnetometer3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IMagnetometer4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerDataThreshold) ReportThreshold() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IMagnetometer4>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IMagnetometer4<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IMagnetometerDataThreshold
    {
        [[nodiscard]] WINRT_IMPL_AUTO(float) XAxisMicroteslas() const;
        WINRT_IMPL_AUTO(void) XAxisMicroteslas(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) YAxisMicroteslas() const;
        WINRT_IMPL_AUTO(void) YAxisMicroteslas(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) ZAxisMicroteslas() const;
        WINRT_IMPL_AUTO(void) ZAxisMicroteslas(float value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IMagnetometerDataThreshold<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IMagnetometerDeviceId
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IMagnetometerDeviceId>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IMagnetometerDeviceId<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IMagnetometerReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) MagneticFieldX() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) MagneticFieldY() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) MagneticFieldZ() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerAccuracy) DirectionalAccuracy() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IMagnetometerReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IMagnetometerReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IMagnetometerReading2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) PerformanceCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IMagnetometerReading2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IMagnetometerReading2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IMagnetometerReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IMagnetometerReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IMagnetometerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Magnetometer) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IMagnetometerStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IMagnetometerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IMagnetometerStatics2
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Magnetometer>) FromIdAsync(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IMagnetometerStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IMagnetometerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IOrientationSensor
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::OrientationSensorReading) GetCurrentReading() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MinimumReportInterval() const;
        WINRT_IMPL_AUTO(void) ReportInterval(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportInterval() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::OrientationSensor, winrt::Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IOrientationSensor, &impl::abi_t<winrt::Windows::Devices::Sensors::IOrientationSensor>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::OrientationSensor, winrt::Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IOrientationSensor>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IOrientationSensor<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IOrientationSensor2
    {
        WINRT_IMPL_AUTO(void) ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) ReadingTransform() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SensorReadingType) ReadingType() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IOrientationSensor2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IOrientationSensor2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IOrientationSensor3
    {
        WINRT_IMPL_AUTO(void) ReportLatency(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportLatency() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxBatchSize() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IOrientationSensor3>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IOrientationSensor3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IOrientationSensorDeviceId
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IOrientationSensorDeviceId>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IOrientationSensorDeviceId<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IOrientationSensorReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SensorRotationMatrix) RotationMatrix() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SensorQuaternion) Quaternion() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IOrientationSensorReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IOrientationSensorReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IOrientationSensorReading2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) PerformanceCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IOrientationSensorReading2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IOrientationSensorReading2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IOrientationSensorReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::OrientationSensorReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IOrientationSensorReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IOrientationSensorReadingYawAccuracy
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerAccuracy) YawAccuracy() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IOrientationSensorReadingYawAccuracy<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IOrientationSensorStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::OrientationSensor) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IOrientationSensorStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IOrientationSensorStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IOrientationSensorStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::OrientationSensor) GetDefaultForRelativeReadings() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IOrientationSensorStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IOrientationSensorStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IOrientationSensorStatics3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::OrientationSensor) GetDefault(winrt::Windows::Devices::Sensors::SensorReadingType const& sensorReadingtype) const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::OrientationSensor) GetDefault(winrt::Windows::Devices::Sensors::SensorReadingType const& sensorReadingType, winrt::Windows::Devices::Sensors::SensorOptimizationGoal const& optimizationGoal) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IOrientationSensorStatics3>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IOrientationSensorStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IOrientationSensorStatics4
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(winrt::Windows::Devices::Sensors::SensorReadingType const& readingType) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(winrt::Windows::Devices::Sensors::SensorReadingType const& readingType, winrt::Windows::Devices::Sensors::SensorOptimizationGoal const& optimizationGoal) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::OrientationSensor>) FromIdAsync(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IOrientationSensorStatics4>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IOrientationSensorStatics4<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IPedometer
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) PowerInMilliwatts() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MinimumReportInterval() const;
        WINRT_IMPL_AUTO(void) ReportInterval(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportInterval() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Pedometer, winrt::Windows::Devices::Sensors::PedometerReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IPedometer, &impl::abi_t<winrt::Windows::Devices::Sensors::IPedometer>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Pedometer, winrt::Windows::Devices::Sensors::PedometerReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IPedometer>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IPedometer<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IPedometer2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<winrt::Windows::Devices::Sensors::PedometerStepKind, winrt::Windows::Devices::Sensors::PedometerReading>) GetCurrentReadings() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IPedometer2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IPedometer2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IPedometerDataThresholdFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::PedometerDataThreshold) Create(winrt::Windows::Devices::Sensors::Pedometer const& sensor, int32_t stepGoal) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IPedometerDataThresholdFactory>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IPedometerDataThresholdFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IPedometerReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::PedometerStepKind) StepKind() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) CumulativeSteps() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) CumulativeStepsDuration() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IPedometerReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IPedometerReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IPedometerReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::PedometerReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IPedometerReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IPedometerReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IPedometerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Pedometer>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Pedometer>) GetDefaultAsync() const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::PedometerReading>>) GetSystemHistoryAsync(winrt::Windows::Foundation::DateTime const& fromTime) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::PedometerReading>>) GetSystemHistoryAsync(winrt::Windows::Foundation::DateTime const& fromTime, winrt::Windows::Foundation::TimeSpan const& duration) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IPedometerStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IPedometerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IPedometerStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::PedometerReading>) GetReadingsFromTriggerDetails(winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const& triggerDetails) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IPedometerStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IPedometerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IProximitySensor
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) MaxDistanceInMillimeters() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) MinDistanceInMillimeters() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ProximitySensorReading) GetCurrentReading() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::ProximitySensor, winrt::Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::IProximitySensor, &impl::abi_t<winrt::Windows::Devices::Sensors::IProximitySensor>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::ProximitySensor, winrt::Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ProximitySensorDisplayOnOffController) CreateDisplayOnOffController() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IProximitySensor>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IProximitySensor<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IProximitySensorDataThresholdFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ProximitySensorDataThreshold) Create(winrt::Windows::Devices::Sensors::ProximitySensor const& sensor) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IProximitySensorDataThresholdFactory>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IProximitySensorDataThresholdFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IProximitySensorReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDetected() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) DistanceInMillimeters() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IProximitySensorReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IProximitySensorReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IProximitySensorReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ProximitySensorReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IProximitySensorReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IProximitySensorStatics
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ProximitySensor) FromId(param::hstring const& sensorId) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IProximitySensorStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IProximitySensorStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IProximitySensorStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ProximitySensorReading>) GetReadingsFromTriggerDetails(winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const& triggerDetails) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IProximitySensorStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IProximitySensorStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ISensorDataThreshold
    {
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ISensorDataThreshold>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ISensorDataThreshold<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ISensorDataThresholdTriggerDetails
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SensorType) SensorType() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ISensorDataThresholdTriggerDetails<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ISensorQuaternion
    {
        [[nodiscard]] WINRT_IMPL_AUTO(float) W() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) X() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) Y() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) Z() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ISensorQuaternion>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ISensorQuaternion<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ISensorRotationMatrix
    {
        [[nodiscard]] WINRT_IMPL_AUTO(float) M11() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) M12() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) M13() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) M21() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) M22() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) M23() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) M31() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) M32() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) M33() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ISensorRotationMatrix>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ISimpleOrientationSensor
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SimpleOrientation) GetCurrentOrientation() const;
        WINRT_IMPL_AUTO(winrt::event_token) OrientationChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::SimpleOrientationSensor, winrt::Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> const& handler) const;
        using OrientationChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor, &impl::abi_t<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor>::remove_OrientationChanged>;
        [[nodiscard]] OrientationChanged_revoker OrientationChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::SimpleOrientationSensor, winrt::Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) OrientationChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ISimpleOrientationSensor<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ISimpleOrientationSensor2
    {
        WINRT_IMPL_AUTO(void) ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) ReadingTransform() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ISimpleOrientationSensor2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ISimpleOrientationSensorDeviceId
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ISimpleOrientationSensorDeviceId<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ISimpleOrientationSensorOrientationChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SimpleOrientation) Orientation() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ISimpleOrientationSensorOrientationChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ISimpleOrientationSensorStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SimpleOrientationSensor) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ISimpleOrientationSensorStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_ISimpleOrientationSensorStatics2
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::SimpleOrientationSensor>) FromIdAsync(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_ISimpleOrientationSensorStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_IWakeOnApproachOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowWhenExternalDisplayConnected() const;
        WINRT_IMPL_AUTO(void) AllowWhenExternalDisplayConnected(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) DisableWhenBatterySaverOn() const;
        WINRT_IMPL_AUTO(void) DisableWhenBatterySaverOn(bool value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::IWakeOnApproachOptions>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_IWakeOnApproachOptions<D>;
    };
}
#endif
