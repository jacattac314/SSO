/**
 * SCIM 2.0 Users endpoints (RFC 7644).
 *
 * GET    /scim/v2/Users          – list users (with filter & pagination)
 * POST   /scim/v2/Users          – create user
 * GET    /scim/v2/Users/:id      – get user
 * PUT    /scim/v2/Users/:id      – replace user (full update)
 * PATCH  /scim/v2/Users/:id      – partial update user
 * DELETE /scim/v2/Users/:id      – delete user
 */
import { Router, Request, Response } from 'express';
import { scimService, ScimError } from '../../services/scim.service';
import { requireScimAuth } from '../../middleware/auth';
import { requireTenant } from '../../middleware/tenant';

const router = Router();

// Apply SCIM authentication to all routes
router.use(requireScimAuth);
router.use(requireTenant);

const SCIM_CONTENT_TYPE = 'application/scim+json';

function handleScimError(res: Response, err: unknown): void {
  if (err instanceof ScimError) {
    res.status(err.status).type(SCIM_CONTENT_TYPE).json(err.toResponse());
  } else {
    res.status(500).type(SCIM_CONTENT_TYPE).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: 500,
      detail: String(err),
    });
  }
}

router.get('/', async (req: Request, res: Response): Promise<void> => {
  try {
    const tenantId = req.tenantId!;
    const filter = req.query['filter'] as string | undefined;
    const startIndex = parseInt(req.query['startIndex'] as string, 10) || 1;
    const count = parseInt(req.query['count'] as string, 10) || 100;

    const result = await scimService.listUsers(tenantId, { filter, startIndex, count });
    res.type(SCIM_CONTENT_TYPE).json(result);
  } catch (err) {
    handleScimError(res, err);
  }
});

router.post('/', async (req: Request, res: Response): Promise<void> => {
  try {
    const tenantId = req.tenantId!;
    const user = await scimService.createUser(tenantId, req.body, { ipAddress: req.ip });
    res.status(201).type(SCIM_CONTENT_TYPE).json(user);
  } catch (err) {
    handleScimError(res, err);
  }
});

router.get('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const user = await scimService.getUser(req.tenantId!, req.params['id']);
    res.type(SCIM_CONTENT_TYPE).json(user);
  } catch (err) {
    handleScimError(res, err);
  }
});

router.put('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const user = await scimService.updateUser(
      req.tenantId!,
      req.params['id'],
      req.body,
      { ipAddress: req.ip }
    );
    res.type(SCIM_CONTENT_TYPE).json(user);
  } catch (err) {
    handleScimError(res, err);
  }
});

router.patch('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const body = req.body as { Operations?: unknown[] };
    const operations = body.Operations ?? [];
    const user = await scimService.patchUser(
      req.tenantId!,
      req.params['id'],
      operations as Array<{ op: string; path?: string; value?: unknown }>,
      { ipAddress: req.ip }
    );
    res.type(SCIM_CONTENT_TYPE).json(user);
  } catch (err) {
    handleScimError(res, err);
  }
});

router.delete('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    await scimService.deleteUser(req.tenantId!, req.params['id'], { ipAddress: req.ip });
    res.status(204).send();
  } catch (err) {
    handleScimError(res, err);
  }
});

export default router;
