import type { NotificationRecord } from './notification.repository';

/**
 * The exact view the API returns, built as an allowlist: a row becomes these
 * fields or it is dropped, and no extra key can ever ride along - the client
 * validates its items strictly and would discard the whole envelope otherwise.
 *
 * The two `*_status` kinds carry exactly one enum `status` param; the three
 * profile kinds carry no params at all, because the client's strict schema
 * rejects an empty object just as it rejects any other extra key.
 */

const UPLOAD_STATUSES: readonly string[] = ['pending', 'approved', 'rejected'];
const SUBSCRIPTION_STATUSES: readonly string[] = [
  'none',
  'pending',
  'active',
  'expired',
  'reversed',
];

export interface NotificationView {
  readonly id: string;
  readonly type: NotificationRecord['kind'];
  /** ISO date-time with an explicit offset, the shape the client parses. */
  readonly createdAt: string;
  readonly read: boolean;
  readonly params?: { readonly status: string };
}

/** A row the client could not render (an unknown param value) maps to `null`. */
export function toNotificationView(record: NotificationRecord): NotificationView | null {
  const view = {
    id: record.id,
    type: record.kind,
    createdAt: record.createdAt.toISOString(),
    read: record.readAt !== null,
  };

  if (record.kind === 'upload_status' || record.kind === 'subscription_status') {
    const status = record.params.status;
    const allowed = record.kind === 'upload_status' ? UPLOAD_STATUSES : SUBSCRIPTION_STATUSES;

    if (typeof status !== 'string' || !allowed.includes(status)) return null;

    return { ...view, params: { status } };
  }

  return view;
}
