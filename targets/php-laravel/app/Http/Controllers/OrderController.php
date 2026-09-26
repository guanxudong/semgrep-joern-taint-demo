<?php

namespace App\Http\Controllers;

use App\Services\OrderService;
use Illuminate\Http\Request;

class OrderController
{
    private OrderService $orders;

    public function __construct()
    {
        $this->orders = new OrderService();
    }

    public function transfer(Request $request)
    {
        $body = $request->all();
        $newBalance = $this->orders->transfer($body['src'], $body['dst'], (float) $body['amount']);
        return response()->json(['balance' => $newBalance]);
    }

    public function coupon(Request $request)
    {
        $body = $request->all();
        $ok = $this->orders->applyCoupon($body['user'], $body['coupon']);
        return response()->json(['applied' => $ok]);
    }

    public function withdraw(Request $request)
    {
        $body = $request->all();
        $ok = $this->orders->withdraw($body['user'], (float) $body['amount']);
        return response()->json(['ok' => $ok]);
    }

    public function withdrawV2(Request $request)
    {
        $body = $request->all();
        $ok = $this->orders->withdrawLocked($body['user'], (float) $body['amount']);
        return response()->json(['ok' => $ok]);
    }
}
