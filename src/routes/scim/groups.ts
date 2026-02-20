/**
 * SCIM 2.0 Groups endpoints (RFC 7644).
 *
 * GET    /scim/v2/Groups          – list groups
 * POST   /scim/v2/Groups          – create group
 * GET    /scim/v2/Groups/:id      – get group
 * PUT    /scim/v2/Groups/:id      – replace group
 * PATCH  /scim/v2/Groups/:id      – partial update group
 * DELETE /scim/v2/Groups/:id      – delete group
 */
import { Router, Request, Response } from 'express';
import { scimService, ScimError } from '../../services/scim.service';
import { requireScimAuth } from '../../middleware/auth';
import { requireTenant } from '../../middleware/tenant';

const router = Router();

router.use(requireScimAuth);
router.use(requireTenant);

const SCIM_CONTENT_TYPE = 'application/scim+json';
const SCIM_LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';

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
    const { query } = await import('../../config/database');
    const startIndex = parseInt(req.query['startIndex'] as string, 10) || 1;
    const count = parseInt(req.query['count'] as string, 10) || 100;
    const offset = startIndex - 1;

    const [countResult, dataResult] = await Promise.all([
      query<{ count: string }>(
        'SELECT COUNT(*) as count FROM scim_groups WHERE tenant_id = $1',
        [tenantId]
      ),
      query(
        `SELECT * FROM scim_groups WHERE tenant_id = $1 ORDER BY created_at LIMIT $2 OFFSET $3`,
        [tenantId, count, offset]
      ),
    ]);

    const total = parseInt(countResult.rows[0]?.count ?? '0', 10);
    const groups = await Promise.all(
      dataResult.rows.map((r) => scimService.getGroup(tenantId, r['id'] as string))
    );

    res.type(SCIM_CONTENT_TYPE).json({
      schemas: [SCIM_LIST_SCHEMA],
      totalResults: total,
      startIndex,
      itemsPerPage: groups.length,
      Resources: groups,
    });
  } catch (err) {
    handleScimError(res, err);
  }
});

router.post('/', async (req: Request, res: Response): Promise<void> => {
  try {
    const group = await scimService.createGroup(req.tenantId!, req.body, { ipAddress: req.ip });
    res.status(201).type(SCIM_CONTENT_TYPE).json(group);
  } catch (err) {
    handleScimError(res, err);
  }
});

router.get('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const group = await scimService.getGroup(req.tenantId!, req.params['id']);
    res.type(SCIM_CONTENT_TYPE).json(group);
  } catch (err) {
    handleScimError(res, err);
  }
});

router.put('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const tenantId = req.tenantId!;
    const groupId = req.params['id'];
    const body = req.body as { displayName?: string; members?: Array<{ value: string }> };
    const { query } = await import('../../config/database');

    const existing = await scimService.getGroup(tenantId, groupId);
    if (!existing) {
      res.status(404).type(SCIM_CONTENT_TYPE).json({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        status: 404,
        detail: `Group ${groupId} not found`,
      });
      return;
    }

    const memberIds = (body.members ?? []).map((m) => m.value);
    await query(
      `UPDATE scim_groups
         SET display_name = COALESCE($3, display_name),
             members = $4,
             updated_at = NOW()
       WHERE id = $1 AND tenant_id = $2`,
      [groupId, tenantId, body.displayName ?? null, memberIds]
    );

    const updated = await scimService.getGroup(tenantId, groupId);
    res.type(SCIM_CONTENT_TYPE).json(updated);
  } catch (err) {
    handleScimError(res, err);
  }
});

router.patch('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    // Simplified PATCH – handle member add/remove operations
    const tenantId = req.tenantId!;
    const groupId = req.params['id'];
    const body = req.body as { Operations?: Array<{ op: string; path?: string; value?: unknown }> };

    for (const op of body.Operations ?? []) {
      if (op.path === 'members') {
        const { query } = await import('../../config/database');
        if (op.op.toLowerCase() === 'add') {
          const additions = (op.value as Array<{ value: string }>).map((v) => v.value);
          await query(
            `UPDATE scim_groups
               SET members = array(SELECT DISTINCT unnest(members || $3::uuid[])),
                   updated_at = NOW()
             WHERE id = $1 AND tenant_id = $2`,
            [groupId, tenantId, additions]
          );
        } else if (op.op.toLowerCase() === 'remove') {
          const removals = (op.value as Array<{ value: string }>).map((v) => v.value);
          await query(
            `UPDATE scim_groups
               SET members = array(SELECT unnest(members) EXCEPT SELECT unnest($3::uuid[])),
                   updated_at = NOW()
             WHERE id = $1 AND tenant_id = $2`,
            [groupId, tenantId, removals]
          );
        }
      }
    }

    const updated = await scimService.getGroup(tenantId, groupId);
    res.type(SCIM_CONTENT_TYPE).json(updated);
  } catch (err) {
    handleScimError(res, err);
  }
});

router.delete('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    await scimService.deleteGroup(req.tenantId!, req.params['id'], { ipAddress: req.ip });
    res.status(204).send();
  } catch (err) {
    handleScimError(res, err);
  }
});

export default router;
