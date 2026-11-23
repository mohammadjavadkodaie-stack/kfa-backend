CREATE OR REPLACE FUNCTION public.kfa_payment_terms_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.expected_amount IS DISTINCT FROM OLD.expected_amount
     OR NEW.expected_currency IS DISTINCT FROM OLD.expected_currency
     OR NEW.expected_network IS DISTINCT FROM OLD.expected_network
     OR NEW.provider IS DISTINCT FROM OLD.provider
     OR NEW.provider_payment_id IS DISTINCT FROM OLD.provider_payment_id
     OR NEW.subscription_id IS DISTINCT FROM OLD.subscription_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'payment terms are immutable after insert'
      USING ERRCODE = 'insufficient_privilege',
            HINT = 'Insert a new payment row instead of rewriting the agreed terms.';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS payments_terms_immutable ON public.payments;
CREATE TRIGGER payments_terms_immutable
BEFORE UPDATE ON public.payments
FOR EACH ROW
EXECUTE FUNCTION public.kfa_payment_terms_immutable();

CREATE OR REPLACE FUNCTION public.kfa_webhook_event_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.provider IS DISTINCT FROM OLD.provider
     OR NEW.event_id IS DISTINCT FROM OLD.event_id
     OR NEW.payload_hash IS DISTINCT FROM OLD.payload_hash
     OR NEW.signature_valid IS DISTINCT FROM OLD.signature_valid
     OR NEW.received_at IS DISTINCT FROM OLD.received_at
     OR (OLD.processed_at IS NOT NULL AND NEW.processed_at IS DISTINCT FROM OLD.processed_at)
     OR (OLD.processed_at IS NOT NULL AND NEW.outcome IS DISTINCT FROM OLD.outcome)
     OR (OLD.processed_at IS NULL AND NEW.processed_at IS NULL AND NEW.outcome IS NOT NULL)
     OR (OLD.processed_at IS NULL AND NEW.processed_at IS NOT NULL AND NEW.outcome IS NULL) THEN
    RAISE EXCEPTION 'webhook event fields are immutable after insert'
      USING ERRCODE = 'insufficient_privilege',
            HINT = 'Only an unprocessed event may be finalized once.';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS webhook_events_immutable ON public.webhook_events;
CREATE TRIGGER webhook_events_immutable
BEFORE UPDATE ON public.webhook_events
FOR EACH ROW
EXECUTE FUNCTION public.kfa_webhook_event_immutable();
