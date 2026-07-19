// Order / wallet logic with deliberate business-logic and race flaws.
const BALANCES: Record<string, number> = { alice: 1000.0, bob: 1000.0 };

// No validation of amount sign -> negative amount steals money.
export function transfer(src: string, dst: string, amount: number): number {
  BALANCES[src] = (BALANCES[src] ?? 0) - amount;
  BALANCES[dst] = (BALANCES[dst] ?? 0) + amount;
  return BALANCES[src];
}

// Coupon is never marked as used -> unlimited reuse.
export function applyCoupon(user: string, coupon: string): boolean {
  if (coupon === 'SAVE50') {
    BALANCES[user] = (BALANCES[user] ?? 0) + 50.0;
    return true;
  }
  return false;
}

// Check-then-act with an await in between -> race condition (TOCTOU).
export async function withdraw(user: string, amount: number): Promise<boolean> {
  const balance = BALANCES[user] ?? 0;
  if (balance >= amount) {
    await new Promise((r) => setImmediate(r)); // attacker fires concurrent requests here
    BALANCES[user] = balance - amount;
    return true;
  }
  return false;
}

let locked = false;

export async function withdrawSafe(user: string, amount: number): Promise<boolean> {
  while (locked) {
    await new Promise((r) => setImmediate(r));
  }
  locked = true;
  try {
    const balance = BALANCES[user] ?? 0;
    if (balance >= amount) {
      BALANCES[user] = balance - amount;
      return true;
    }
    return false;
  } finally {
    locked = false;
  }
}
