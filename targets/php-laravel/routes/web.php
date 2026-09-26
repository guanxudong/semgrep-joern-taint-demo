<?php

use App\Http\Controllers\AdminController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\FileController;
use App\Http\Controllers\OrderController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\RenderController;
use App\Http\Controllers\ToolController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\XmlController;
use Illuminate\Support\Facades\Route;

Route::get('/users/search', [UserController::class, 'search']);
Route::get('/users/lookup', [UserController::class, 'lookup']);
Route::get('/users/v2/search', [UserController::class, 'searchV2']);
Route::get('/users/me/{id}', [UserController::class, 'me']);
Route::get('/users/{id}', [UserController::class, 'show']);

Route::get('/render/hello', [RenderController::class, 'hello']);
Route::get('/render/preview', [RenderController::class, 'preview']);

Route::get('/tools/ping', [ToolController::class, 'ping']);
Route::get('/tools/diagnose', [ToolController::class, 'diagnose']);
Route::post('/tools/calc', [ToolController::class, 'calc']);

Route::get('/files/download', [FileController::class, 'download']);
Route::get('/files/v2/download', [FileController::class, 'downloadV2']);

Route::post('/xml/parse', [XmlController::class, 'parse']);
Route::post('/xml/v2/parse', [XmlController::class, 'parseV2']);

Route::post('/profile/update', [ProfileController::class, 'update']);
Route::post('/profile/import', [ProfileController::class, 'import']);

Route::post('/orders/transfer', [OrderController::class, 'transfer']);
Route::post('/orders/coupon', [OrderController::class, 'coupon']);
Route::post('/orders/withdraw', [OrderController::class, 'withdraw']);
Route::post('/orders/v2/withdraw', [OrderController::class, 'withdrawV2']);

Route::get('/admin/users', [AdminController::class, 'listUsers']);
Route::delete('/admin/users/{id}', [AdminController::class, 'destroy']);

Route::post('/auth/login', [AuthController::class, 'login']);
Route::post('/auth/reset', [AuthController::class, 'requestReset']);
