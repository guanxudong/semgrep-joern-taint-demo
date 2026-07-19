// Order/wallet routes: business-logic bypass, race condition, safe variant.
import { Router, Request, Response } from 'express';
import { transfer, applyCoupon, withdraw, withdrawSafe } from '../services/orderService';

const router = Router();

// VULN: js-business-logic-01 (business-logic, cwe-840) - negative amount accepted
router.post('/transfer', (req: Request, res: Response) => {
  const { src, dst, amount } = req.body;
  res.json({ balance: transfer(src, dst, Number(amount)) });
});

// VULN: js-business-logic-01 (business-logic, cwe-840) - coupon never invalidated
router.post('/coupon', (req: Request, res: Response) => {
  const { user, coupon } = req.body;
  res.json({ applied: applyCoupon(user, coupon) });
});

// VULN: js-race-condition-01 (race-condition, cwe-367)
router.post('/withdraw', async (req: Request, res: Response) => {
  const { user, amount } = req.body;
  res.json({ ok: await withdraw(user, Number(amount)) });
});

// SAFE: js-safe-05 (mimics race-condition) - mutex-guarded withdraw
router.post('/withdraw_safe', async (req: Request, res: Response) => {
  const { user, amount } = req.body;
  res.json({ ok: await withdrawSafe(user, Number(amount)) });
});

export default router;
