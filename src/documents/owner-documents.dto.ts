import { IsUUID } from 'class-validator';

/**
 * The only thing a caller may say about the document: its id, and it comes from
 * the path.
 *
 * There is no owner here, because the owner is the authenticated principal, and
 * nothing else to address: a document of another account and a document that
 * does not exist are answered the same way by the service.
 */
export class DocumentDeleteParamsDto {
  /** The table generates any versioned UUID; this accepts them all. */
  @IsUUID()
  documentId!: string;
}

/**
 * The list route takes no parameters at all.
 *
 * The class is empty on purpose: the global pipe runs with `whitelist` and
 * `forbidNonWhitelisted`, so a query or body field it does not declare is
 * refused with a 400 instead of being ignored. There is no owner to name, no
 * filter to smuggle and no quota to probe.
 */
export class NoDocumentParametersDto {}
