// Order/wallet routes.
import { Router, Request, Response } from 'express';
import { transfer, applyCoupon, withdraw, withdrawSafe } from '../services/orderService';

const router = Router();

router.post('/transfer', (req: Request, res: Response) => {
  const { src, dst, amount } = req.body;
  res.json({ balance: transfer(src, dst, Number(amount)) });
});

router.post('/coupon', (req: Request, res: Response) => {
  const { user, coupon } = req.body;
  res.json({ applied: applyCoupon(user, coupon) });
});

router.post('/withdraw', async (req: Request, res: Response) => {
  const { user, amount } = req.body;
  res.json({ ok: await withdraw(user, Number(amount)) });
});

router.post('/withdraw_safe', async (req: Request, res: Response) => {
  const { user, amount } = req.body;
  res.json({ ok: await withdrawSafe(user, Number(amount)) });
});

export default router;
