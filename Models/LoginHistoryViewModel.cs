using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace qlthietbi_2.Models
{
    public class LoginHistoryViewModel
    {
        public int AccountID { get; set; }
        public string Username { get; set; }
        public DateTime LoginTime { get; set; }
        public DateTime? LogoutTime { get; set; }
        public string IPAddress { get; set; }
        public int? DurationMinutes { get; set; }
        public string Status { get; set; }

        public string DurationDisplay
        {
            get
            {
                if (!DurationMinutes.HasValue) return "Đang hoạt động";

                var duration = TimeSpan.FromMinutes(DurationMinutes.Value);
                return $"{duration.Hours}h {duration.Minutes}m {duration.Seconds}s";
            }
        }
    }

}