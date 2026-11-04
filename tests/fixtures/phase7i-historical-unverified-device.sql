-- Disposable CI only. Emulates one historical unverified device record,
-- which must NEVER be upgraded into a first verified signer by direct SQL.
-- Run BEFORE installation of Phase7I hard-stop trigger.
INSERT INTO public.messaging_devices(id,user_id,public_key_jwk,key_algorithm,device_label)
VALUES (
 'abababab-abab-4bab-8bab-abababababab',
 '99999999-9999-4999-8999-999999999999',
 jsonb_build_object('kty','EC','crv','P-256','x',repeat('G',43),'y',repeat('H',43)),
 'ECDH-P256','historical unverified synthetic device'
);
DO $guard$
BEGIN
 IF (SELECT count(*) FROM public.messaging_devices
    WHERE user_id='99999999-9999-4999-8999-999999999999')<>1
 OR EXISTS(SELECT 1 FROM public.messaging_device_signing_keys
    WHERE user_id='99999999-9999-4999-8999-999999999999'
    AND verified_at IS NOT NULL)
 THEN RAISE EXCEPTION 'FAIL: dirty synthetic historical device fixture'; END IF;
END
$guard$;
