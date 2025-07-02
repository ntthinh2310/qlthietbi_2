using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace qlthietbi_2.ViewModels
{
    public class DeviceViewModel
    {
        public int DeviceID { get; set; }

        [Required(ErrorMessage = "Tên thiết bị là bắt buộc")]
        public string DeviceName { get; set; }

        public string Manufacturer { get; set; }
        public string Model { get; set; }

        [DataType(DataType.Date)]
        public DateTime? PurchaseDate { get; set; }

        [DataType(DataType.Date)]
        public DateTime? WarrantyUntil { get; set; }

        [Required(ErrorMessage = "Trạng thái là bắt buộc")]
        public string Status { get; set; }

        public string Notes { get; set; }

        [Required(ErrorMessage = "Loại thiết bị là bắt buộc")]
        public int? TypeID { get; set; } // Sử dụng int? để cho phép null
        public string TypeName { get; set; } // Nếu cần hiển thị
    }

}
