/**
 * Liking a public profile photo.
 *
 * Only an APPROVED photo can be liked. The status is read on every request and
 * never cached, so a staff takedown (REMOVED) stops the very next like; a
 * missing id and a PENDING, REJECTED or REMOVED photo are the same generic 404.
 * The owner of the photo cannot like it either - one more refusal behind the
 * same 404, so no answer says which id exists or whom it belongs to. A repeated
 * like is a silent no-op, decided by the unique pair in the database.
 *
 * The count route answers a number only, and works on the owner's own photo: it
 * never says who liked.
 */

import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { PolicySubject } from '../../auth/policy/access-policy';
import {
  PHOTO_LIKE_REPOSITORY,
  type LikeablePhoto,
  type PhotoLikeRepository,
} from './photo-like.repository';

export interface PhotoLikeCountView {
  readonly likeCount: number;
}

@Injectable()
export class PhotoLikeService {
  constructor(
    @Inject(PHOTO_LIKE_REPOSITORY)
    private readonly likes: PhotoLikeRepository,
  ) {}

  async like(actor: PolicySubject, photoId: string): Promise<void> {
    const photo = await this.likeablePhoto(actor, photoId);

    await this.likes.create(photo.id, actor.id);
  }

  async unlike(actor: PolicySubject, photoId: string): Promise<void> {
    const photo = await this.likeablePhoto(actor, photoId);

    await this.likes.remove(photo.id, actor.id);
  }

  async count(photoId: string): Promise<PhotoLikeCountView> {
    const photo = await this.approvedPhoto(photoId);

    return { likeCount: await this.likes.count(photo.id) };
  }

  /** An approved photo that is not the caller's own; never any detail. */
  private async likeablePhoto(actor: PolicySubject, photoId: string): Promise<LikeablePhoto> {
    const photo = await this.approvedPhoto(photoId);

    if (photo.userId === actor.id) throw new NotFoundException();

    return photo;
  }

  /** The current status decides, on every call; nothing is cached. */
  private async approvedPhoto(photoId: string): Promise<LikeablePhoto> {
    const photo = await this.likes.findPhoto(photoId);

    if (photo === null || photo.status !== 'APPROVED') throw new NotFoundException();

    return photo;
  }
}
