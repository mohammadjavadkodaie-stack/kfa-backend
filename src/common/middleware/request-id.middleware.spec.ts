import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import {
  REQUEST_ID_HEADER,
  getRequestId,
  isUuid,
  requestIdMiddleware,
  resolveRequestId,
} from './request-id.middleware';

const VALID_UUID = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';

function createRequest(headers: Record<string, string | string[] | undefined>): Request {
  return { headers } as unknown as Request;
}

function createResponse(): { response: Response; setHeader: jest.Mock } {
  const setHeader = jest.fn();

  return { response: { setHeader } as unknown as Response, setHeader };
}

describe('request id middleware', () => {
  describe('resolveRequestId', () => {
    it('keeps a valid client supplied uuid, normalised to lowercase', () => {
      expect(resolveRequestId(VALID_UUID.toUpperCase())).toBe(VALID_UUID);
    });

    it('replaces an invalid client supplied value', () => {
      const requestId = resolveRequestId('<script>alert(1)</script>');

      expect(requestId).not.toContain('script');
      expect(isUuid(requestId)).toBe(true);
    });

    it('generates a uuid when the header is missing', () => {
      expect(isUuid(resolveRequestId(undefined))).toBe(true);
    });

    it('uses the first value when the header is repeated', () => {
      expect(resolveRequestId([VALID_UUID, randomUUID()])).toBe(VALID_UUID);
    });
  });

  describe('requestIdMiddleware', () => {
    it('assigns the id to the request and echoes it on the response', () => {
      const request = createRequest({ [REQUEST_ID_HEADER]: VALID_UUID });
      const { response, setHeader } = createResponse();
      const next = jest.fn() as unknown as NextFunction;

      requestIdMiddleware(request, response, next);

      expect(getRequestId(request)).toBe(VALID_UUID);
      expect(setHeader).toHaveBeenCalledWith(REQUEST_ID_HEADER, VALID_UUID);
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('assigns a generated id when the client value is not a uuid', () => {
      const request = createRequest({ [REQUEST_ID_HEADER]: 'not-a-uuid' });
      const { response, setHeader } = createResponse();

      requestIdMiddleware(request, response, jest.fn() as unknown as NextFunction);

      const assigned = getRequestId(request);
      expect(assigned).not.toBe('not-a-uuid');
      expect(setHeader).toHaveBeenCalledWith(REQUEST_ID_HEADER, assigned);
    });

    it('reports "unknown" when no id was assigned', () => {
      expect(getRequestId({})).toBe('unknown');
    });
  });
});
