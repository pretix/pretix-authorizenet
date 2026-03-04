import hashlib
import hmac
import json
import logging
from decimal import Decimal
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django_scopes import scopes_disabled
from pretix.base.models import OrderPayment, OrderRefund

from .models import ReferencedAuthorizeNetObject

logger = logging.getLogger(__name__)


@csrf_exempt
@require_POST
@scopes_disabled()
def webhook(request, *args, **kwargs):
    # Always return 200 because AuthorizeNet just silently disables the webhook otherwise
    data = json.loads(request.body.decode())
    if data["payload"]["entityName"] != "transaction":
        return HttpResponse("Not interested.", status=200)

    payment = None
    try:
        payment = ReferencedAuthorizeNetObject.objects.get(
            reference=data["payload"]["id"]
        ).payment
    except ReferencedAuthorizeNetObject.DoesNotExist:
        # Far from perfect, but necessary for refund processing
        if "invoiceNumber" not in data["payload"]:
            return HttpResponse("Unknown payment.", status=200)
        if "-R-" in data["payload"]["invoiceNumber"]:
            r = OrderRefund.objects.filter(
                order__code=data["payload"]["invoiceNumber"].split("-")[0],
                local_id=data["payload"]["invoiceNumber"].split("-")[2],
                provider__startswith="authorizenet_",
            ).first()
            if r:
                payment = r.payment
        if not payment:
            rano = ReferencedAuthorizeNetObject.objects.filter(
                order__code=data["payload"]["invoiceNumber"].split("-")[0]
            ).first()
            if rano:
                payment = rano.payment
        if not payment:
            logger.info(f"Received authorize.net webhook for unknown payment: {data}")
            return HttpResponse("Unknown payment.", status=200)

    provider = payment.payment_provider

    received_signature = request.headers["X-Anet-Signature"].split("=")[-1].upper()
    computed_signature = (
        hmac.new(provider.settings.signature_key.encode(), request.body, hashlib.sha512)
        .hexdigest()
        .upper()
    )
    if received_signature != computed_signature:
        logger.info(f"Received authorize.net webhook with invalid signature: {data}")
        return HttpResponse("Invalid signature", status=200)

    payment.order.log_action("pretix_authorizenet.event", data=data)

    if data["eventType"] == "net.authorize.payment.void.created":
        payment.create_external_refund(payment.amount, info=json.dumps(data["payload"]))
    elif data["eventType"] == "net.authorize.payment.refund.created":
        payment.create_external_refund(
            Decimal(data["payload"]["authAmount"]), info=json.dumps(data["payload"])
        )
    elif data[
        "eventType"
    ] == "net.authorize.payment.fraud.declined" and payment.state not in (
        OrderPayment.PAYMENT_STATE_CONFIRMED,
        OrderPayment.PAYMENT_STATE_REFUNDED,
    ):
        payment.fail()

    return HttpResponse("OK", status=200)
