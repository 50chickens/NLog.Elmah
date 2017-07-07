// Copyright 2013 Kim Christensen, Todd Meinershagen, et. al.
//  
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use 
// this file except in compliance with the License. You may obtain a copy of the 
// License at 
// 
//     http://www.apache.org/licenses/LICENSE-2.0 
// 
// Unless required by applicable law or agreed to in writing, software distributed 
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR 
// CONDITIONS OF ANY KIND, either express or implied. See the License for the 
// specific language governing permissions and limitations under the License.

using System;
using System.Web;


using Elmah;
using NLog.Targets;

namespace NLog.Elmah
{
    /// <summary>
    /// Write messages to Elmah.
    /// </summary>
    [Target("Elmah")]
    public sealed class ElmahTarget : TargetWithLayout
    {
        private readonly ErrorLog _errorLog;

        /// <summary>
        /// Use <see cref="LogEventInfo.Level"/> as type if <see cref="LogEventInfo.Exception"/> is <c>null</c>.
        /// </summary>
        public bool LogLevelAsType { get; set; }

        /// <summary>
        /// Target with default errorlog.
        /// </summary>
        public ElmahTarget()
            : this(ErrorLog.GetDefault(null))
        { }

        /// <summary>
        /// Target with errorLog.
        /// </summary>
        /// <param name="errorLog"></param>
        public ElmahTarget(ErrorLog errorLog)
        {
            try
            {
                errorLog.ApplicationName = "Nlog";
            }
            catch 
            {
                //if elmah module application name is already initialized. 
            }
            _errorLog = errorLog;
            LogLevelAsType = false;
        }

        /// <summary>
        /// Write the event.
        /// </summary>
        /// <param name="logEvent">event to be written.</param>
        protected override void Write(LogEventInfo logEvent)
        {
            var logMessage = Layout.Render(logEvent);

            var httpContext = HttpContext.Current;
            var error = logEvent.Exception == null ? new Error() : httpContext != null ? new Error(logEvent.Exception, httpContext) : new Error(logEvent.Exception);
            var type = error.Exception != null
                           ? error.Exception.GetType().FullName
                           : LogLevelAsType ? logEvent.Level.Name : string.Empty;
            error.Type = type;
            error.Message = logMessage;
            error.Time = GetCurrentDateTime == null ? logEvent.TimeStamp : GetCurrentDateTime();
            error.HostName = Environment.MachineName;
            error.Detail = logEvent.Exception == null ? logMessage : logEvent.Exception.StackTrace;

            

            if (error.User == "")
            {
                string ip = GetIP();
                error.User = ip;
            }
            error.Source = logEvent.LoggerName;
            _errorLog.Log(error);
        }

        /// <summary>
        /// Method for retrieving current date and time. If <c>null</c>, then <see cref="LogEventInfo.TimeStamp"/> will be used.
        /// </summary>
        public Func<DateTime> GetCurrentDateTime { get; set; }
        /// <summary>
        /// Method for retrieving current ip address of caller. will use ip address of forwarded for (proxy) if header is found. otherwise, will use remote ip address.
        /// </summary>
        public static String GetIP()
        {
            String ip =
                HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];

            if (string.IsNullOrEmpty(ip))
            {
                ip = HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];
            }
            if (ip.Equals(@"::1")) return ip;
            if (ip.Contains(":") )
            {
                //ipaddress can be composed of ip:srcport. so grab just the ip component if so. 
                return ip.Split(':')[0];
            }
            return ip;
        }
    }
}
