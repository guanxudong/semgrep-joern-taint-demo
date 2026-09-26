using BadDemo.Services;
using Microsoft.AspNetCore.Mvc;

namespace BadDemo.Controllers
{
    [ApiController]
    [Route("orders")]
    public class OrdersController : ControllerBase
    {
        private readonly OrderService _orderService = new OrderService();

        [HttpPost("transfer")]
        public IActionResult Transfer([FromBody] TransferRequest req)
        {
            return Ok(_orderService.Transfer(req.Src, req.Dst, req.Amount));
        }

        [HttpPost("coupon")]
        public IActionResult Coupon([FromBody] CouponRequest req)
        {
            return Ok(_orderService.ApplyCoupon(req.User, req.Coupon));
        }

        [HttpPost("withdraw")]
        public IActionResult Withdraw([FromBody] WithdrawRequest req)
        {
            return Ok(_orderService.Withdraw(req.User, req.Amount));
        }

        [HttpPost("withdraw_safe")]
        public IActionResult WithdrawSafe([FromBody] WithdrawRequest req)
        {
            return Ok(_orderService.WithdrawSafe(req.User, req.Amount));
        }

        public class TransferRequest
        {
            public string Src { get; set; } = "";
            public string Dst { get; set; } = "";
            public double Amount { get; set; }
        }

        public class CouponRequest
        {
            public string User { get; set; } = "";
            public string Coupon { get; set; } = "";
        }

        public class WithdrawRequest
        {
            public string User { get; set; } = "";
            public double Amount { get; set; }
        }
    }
}
