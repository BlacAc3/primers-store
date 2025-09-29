## Summary
This design breaks down into the seven core modules: Authentication, Vendor Management, Product Listings, Customer Storefront, Payment Gateway Integration, Admin Dashboard, and Notifications. Under each, you’ll find the full set of CRUD (Create, Read, Update, Delete) and workflow endpoints you’ll need to implement secure, role-based access (Customer, Vendor, Admin), subscription billing, and real-time notifications.

---

## 1. Authentication & Authorization
| Method | Endpoint                        | Description                                   | Roles                   |
|--------|---------------------------------|-----------------------------------------------|-------------------------|
| POST   | `/api/auth/register`            | Register a new user (body includes `role`)    | Public                  |
| POST   | `/api/auth/login`               | Log in (returns JWT / OAuth token)            | Public                  |
| POST   | `/api/auth/logout`              | Invalidate current session/token              | Authenticated           |
| GET    | `/api/auth/me`                  | Get current user profile                      | Authenticated           |
| POST   | `/api/auth/refresh-token`       | Refresh JWT using refresh token               | Authenticated           |
| POST   | `/api/auth/password-reset`      | Send password-reset email/SMS                 | Public                  |
| POST   | `/api/auth/password-reset/confirm` | Submit new password with reset token        | Public                  |

---

## 2. Vendor Management
| Method | Endpoint                                                | Description                                     | Roles   |
|--------|---------------------------------------------------------|-------------------------------------------------|---------|
| POST   | `/api/vendors/register`                                 | Submit vendor registration request              | Public  |
| GET    | `/api/vendors`                                          | List all vendors (with status filter)           | Admin   |
| GET    | `/api/vendors/:vendorId`                                | Get vendor details                              | Admin   |
| PUT    | `/api/vendors/:vendorId/approve`                        | Approve vendor                                   | Admin   |
| PUT    | `/api/vendors/:vendorId/reject`                         | Reject vendor                                    | Admin   |
| PUT    | `/api/vendors/:vendorId/suspend`                        | Suspend vendor (e.g., non-payment)               | Admin   |
| PUT    | `/api/vendors/:vendorId/ban`                            | Ban vendor                                       | Admin   |
| DELETE | `/api/vendors/:vendorId`                                | Remove vendor                                    | Admin   |
| GET    | `/api/vendors/:vendorId/products`                       | List products for a given vendor                 | Vendor, Admin |
| GET    | `/api/vendors/:vendorId/reviews`                        | List reviews for a specific vendor               | Public  |
| POST   | `/api/vendors/:vendorId/reviews`                        | Add a review for a specific vendor               | Customer |
---

## 3. Product Listings & Categories
### Products
| Method | Endpoint                                      | Description                                         | Roles                   |
|--------|-----------------------------------------------|-----------------------------------------------------|-------------------------|
| POST   | `/api/products`                               | Create new product                                 | Vendor                  |
| GET    | `/api/products`                               | List/search products (query: `category`, `vendor`, `tags`, `priceMin`, `priceMax`, `q`) | Public                  |
| GET    | `/api/products/:productId`                   | Get product details                                 | Public                  |
| PUT    | `/api/products/:productId`                   | Update product (price, stock, description, photos) | Vendor (own) / Admin    |
| DELETE | `/api/products/:productId`                   | Disable or remove product                          | Vendor (own) / Admin    |
| POST   | `/api/products/:productId/reviews`            | Add a review for a specific product               | Customer                |
| GET    | `/api/products/:productId/reviews`            | List reviews for a specific product                | Public                  |

### Categories & Tags
| Method | Endpoint                          | Description                   | Roles     |
|--------|-----------------------------------|-------------------------------|-----------|
| GET    | `/api/categories`                 | List all categories           | Public    |
| POST   | `/api/categories`                 | Create a new category         | Admin     |
| GET    | `/api/categories/:categoryId`     | Get category details          | Public    |
| PUT    | `/api/categories/:categoryId`     | Update category               | Admin     |
| DELETE | `/api/categories/:categoryId`     | Remove category               | Admin     |
| GET    | `/api/tags`                       | List all tags                 | Public    |
| POST   | `/api/tags`                       | Create a new tag              | Admin     |
| PUT    | `/api/tags/:tagId`                | Update tag                    | Admin     |
| DELETE | `/api/tags/:tagId`                | Remove tag                    | Admin     |

---

## 4. Customer Storefront & Orders
### Cart & Wishlist
| Method | Endpoint                                  | Description                         | Roles     |
|--------|-------------------------------------------|-------------------------------------|-----------|
| GET    | `/api/cart`                               | Get current user’s cart items       | Customer  |
| POST   | `/api/cart/add`                           | Add product to cart (`productId`, `qty`) | Customer |
| PUT    | `/api/cart/update/:itemId`                | Update cart item quantity           | Customer  |
| DELETE | `/api/cart/remove/:itemId`                | Remove item from cart               | Customer  |
| GET    | `/api/wishlist`                           | Get wishlist                        | Customer  |
| POST   | `/api/wishlist/:productId`                | Add product to wishlist             | Customer  |
| DELETE | `/api/wishlist/:productId`                | Remove from wishlist                | Customer  |

### Orders & Checkout
| Method | Endpoint                                  | Description                             | Roles     |
|--------|-------------------------------------------|-----------------------------------------|-----------|
| POST   | `/api/orders`                             | Place an order (checkout)               | Customer  |
| GET    | `/api/orders`                             | List user’s past orders                 | Customer  |
| GET    | `/api/orders/:orderId`                   | Get order details/track shipping        | Customer, Admin, Vendor (own) |
| PUT    | `/api/orders/:orderId/status`            | Update order status (e.g., shipped)     | Admin, Vendor (own) |

---

## 5. Payment Gateway Integration
| Method | Endpoint                                            | Description                                               | Roles        |
|--------|-----------------------------------------------------|-----------------------------------------------------------|--------------|
| POST   | `/api/payments/initiate`                            | Initiate payment (body: `orderId`, `method`, `amount`)    | Customer     |
| GET    | `/api/payments/:paymentId`                          | Get payment details                                       | Customer, Admin, Vendor |
| GET    | `/api/payments/:paymentId/status`                   | Get payment status                                        | Customer, Admin, Vendor |
| POST   | `/api/payments/webhook/paystack`                    | Paystack callback/webhook                                | Public (Paystack) |
| POST   | `/api/payments/webhook/flutterwave`                 | Flutterwave webhook                                      | Public (Flutterwave) |
| POST   | `/api/payments/webhook/stripe`                      | Stripe webhook                                           | Public (Stripe) |
| POST   | `/api/payments/webhook/paypal`                      | PayPal webhook                                           | Public (PayPal) |
| GET    | `/api/subscriptions`                                | List current user’s subscriptions                        | Vendor, Admin |
| POST   | `/api/subscriptions`                                | Create/update vendor subscription plan (recurring billing)| Vendor       |
| PUT    | `/api/subscriptions/:subscriptionId`               | Modify subscription                                      | Vendor       |
| DELETE | `/api/subscriptions/:subscriptionId`               | Cancel subscription                                      | Vendor       |

---

## 6. Admin Dashboard & Analytics
| Method | Endpoint                                      | Description                                    | Roles |
|--------|-----------------------------------------------|------------------------------------------------|-------|
| GET    | `/api/admin/vendors/analytics`                | Sales, dues per vendor                         | Admin |
| GET    | `/api/admin/transactions`                     | All payment transactions                       | Admin |
| GET    | `/api/admin/orders`                           | All orders (with filtering by status/date)     | Admin |
| GET    | `/api/admin/sales/summary`                    | Total revenue, commissions, subscriptions      | Admin |
| PUT    | `/api/admin/users/:userId/role`               | Grant/Revoke roles (e.g., promote to Admin)    | Admin |
| GET    | `/api/admin/logs`                             | Audit logs of admin actions                    | Admin |

---

## 7. Notifications System
| Method | Endpoint                                  | Description                                            | Roles       |
|--------|-------------------------------------------|--------------------------------------------------------|-------------|
| GET    | `/api/notifications`                      | Fetch logged-in user’s notifications                   | Authenticated |
| POST   | `/api/notifications/email`                | Send an internal email (for system use)                | Admin        |
| POST   | `/api/notifications/sms`                  | Send an internal SMS                                   | Admin        |
| PUT    | `/api/notifications/:notificationId/read` | Mark notification as read                              | Authenticated |
| GET    | `/api/notifications/settings`             | Get/update user’s notification preferences             | Authenticated |

---

### Health & Utility
| Method | Endpoint               | Description                         | Roles         |
|--------|------------------------|-------------------------------------|---------------|
| GET    | `/api/health`          | Service health check (uptime)       | Public        |
| GET    | `/api/status`          | Version, uptime, and dependency status | Public     |

---

**Next Steps:**
1. **Swagger/OpenAPI**: Convert this spec into a formal OpenAPI (Swagger) document for API docs and codegen.
2. **RBAC Middleware**: Implement middleware that checks JWT scopes/roles on each endpoint.
3. **Webhooks & Queues**: Hook payment webhooks into a message queue (e.g., RabbitMQ) for reliable processing.
4. **Rate Limiting & Security**: Apply rate limits (e.g., express-rate-limit or Django DRF throttling) and 2FA on sensitive routes.
