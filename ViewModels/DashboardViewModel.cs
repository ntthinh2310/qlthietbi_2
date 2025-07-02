using System.Collections.Generic;

namespace qlthietbi_2.ViewModels
{
    public class DashboardViewModel
    {
        public int TotalDevices { get; set; }
        public int TotalDeviceTypes { get; set; }
        public int ActiveDevices { get; set; }
        public int MaintenanceDevices { get; set; }
        public int ActiveDevicePercentage { get; set; }
        public List<string> TypeNames { get; set; } = new List<string>();
        public List<int> DeviceCounts { get; set; } = new List<int>();
        public List<DeviceDistributionItem> DeviceDistribution { get; set; } = new List<DeviceDistributionItem>();
    }

    public class DeviceDistributionItem
    {
        public string TypeName { get; set; }
        public int Count { get; set; }
        public string Color { get; set; } // For pie chart
        public string HoverColor { get; set; } // For pie chart
        public string BarColor { get; set; } // For column chart
        public string BarHoverColor { get; set; } // For column chart
    }
}