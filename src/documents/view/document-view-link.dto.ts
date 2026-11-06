import { IsUUID } from 'class-validator';

/**
 * The only thing a caller may say about the document: its id, and it comes from
 * the path.
 *
 * There is no owner, no object key, no file name and no token here, because the
 * viewer is the authenticated principal and the object key never leaves the
 * storage layer. The global pipe runs with `whitelist` and
 * `forbidNonWhitelisted`, so a field this class does not declare is refused
 * instead of ignored - there is nowhere to address another account.
 */
export class DocumentViewLinkParamsDto {
  /**
   * The table generates a v4 UUID (`gen_random_uuid()`); any versioned UUID is
   * accepted, so a future generator change cannot lock existing ids out.
   */
  @IsUUID()
  documentId!: string;
}
