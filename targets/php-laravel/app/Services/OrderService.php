<?php

namespace App\Services;

use App\Repositories\Db;

class OrderService
{
    private static array $balances = ['alice' => 1000.0, 'bob' => 1000.0];

    public function transfer(string $src, string $dst, float $amount): float
    {
        $srcBalance = self::$balances[$src] ?? 0.0;
        self::$balances[$src] = $srcBalance - $amount;
        self::$balances[$dst] = (self::$balances[$dst] ?? 0.0) + $amount;
        return self::$balances[$src];
    }

    public function applyCoupon(string $user, string $coupon): bool
    {
        if ($coupon === 'SAVE50') {
            self::$balances[$user] = (self::$balances[$user] ?? 0.0) + 50.0;
            return true;
        }
        return false;
    }

    public function withdraw(string $user, float $amount): bool
    {
        $balance = self::$balances[$user] ?? 0.0;
        if ($balance >= $amount) {
            $newBalance = $balance - $amount;
            Db::execute("UPDATE balances SET amount = " . $newBalance . " WHERE user = '" . $user . "'");
            self::$balances[$user] = $newBalance;
            return true;
        }
        return false;
    }

    public function withdrawLocked(string $user, float $amount): bool
    {
        $lock = fopen('/tmp/orderdemo.lock', 'c');
        flock($lock, LOCK_EX);
        try {
            $balance = self::$balances[$user] ?? 0.0;
            if ($balance >= $amount) {
                self::$balances[$user] = $balance - $amount;
                return true;
            }
            return false;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
