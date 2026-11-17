use std::collections::HashMap;

use mc_authz::{resolve_resource, resolve_server, Overwrite, Permissions};
use mc_db::repos::permissions::OverwriteRecord;
use mc_db::repos::playlists::PlaylistRecord;
use mc_db::repos::roles::RoleRecord;
use mc_db::repos::{libraries, permissions, roles};
use mc_db::PgPool;
use uuid::Uuid;

use crate::error::ApiError;

#[derive(Clone, Debug)]
pub struct LibraryAccess {
    pub id: Uuid,
    pub name: String,
    pub permissions: Permissions,
}

#[derive(Clone, Debug)]
pub struct AuthzContext {
    pub user_id: Uuid,
    pub server: Permissions,
    pub roles: Vec<RoleRecord>,
    pub role_ids: Vec<Uuid>,
    pub everyone_role_id: Uuid,
    pub libraries: Vec<LibraryAccess>,
}

impl AuthzContext {
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.server.is_admin()
    }

    #[must_use]
    pub fn visible_library_ids(&self) -> Vec<Uuid> {
        self.libraries
            .iter()
            .filter(|library| library.permissions.can_view_library())
            .map(|library| library.id)
            .collect()
    }

    #[must_use]
    pub fn library_permissions(&self, library_id: Uuid) -> Permissions {
        if self.is_admin() {
            return Permissions::ALL;
        }

        self.libraries
            .iter()
            .find(|library| library.id == library_id)
            .map_or(Permissions::NONE, |library| library.permissions)
    }

    #[must_use]
    pub fn can_library(&self, library_id: Uuid, permission: Permissions) -> bool {
        self.is_admin() || self.library_permissions(library_id).contains(permission)
    }

    #[must_use]
    pub fn can(&self, permission: Permissions) -> bool {
        self.is_admin() || self.server.contains(permission)
    }
}

pub async fn load_cached(
    pool: &PgPool,
    cache: &crate::authz_cache::AuthzCache,
    user_id: Uuid,
) -> Result<AuthzContext, ApiError> {
    if let Some(context) = cache.get(user_id) {
        return Ok(context);
    }

    let context = load(pool, user_id).await?;
    cache.put(user_id, context.clone());
    Ok(context)
}

pub async fn load(pool: &PgPool, user_id: Uuid) -> Result<AuthzContext, ApiError> {
    let everyone = roles::everyone(pool)
        .await?
        .ok_or_else(|| ApiError::internal("everyone role is missing"))?;
    let user_roles = roles::for_user(pool, user_id).await?;
    let role_ids = user_roles.iter().map(|role| role.id).collect::<Vec<_>>();

    let server = resolve_server(
        std::iter::once(permissions_from_i64(everyone.permissions)).chain(
            user_roles
                .iter()
                .map(|role| permissions_from_i64(role.permissions)),
        ),
    );

    let libraries = libraries::list(pool).await?;
    let mut overwrite_role_ids = role_ids.clone();
    overwrite_role_ids.push(everyone.id);
    let overwrites =
        permissions::list_for_user(pool, "library", user_id, &overwrite_role_ids).await?;
    let mut access = Vec::with_capacity(libraries.len());

    for library in libraries {
        let everyone_overwrite = overwrite_for(&overwrites, library.id, "role", everyone.id);
        let role_overwrites = role_ids
            .iter()
            .filter_map(|role_id| overwrite_for(&overwrites, library.id, "role", *role_id))
            .collect::<Vec<_>>();
        let user_overwrite = overwrite_for(&overwrites, library.id, "user", user_id);

        let permissions = resolve_resource(
            server,
            Permissions::LIBRARY_VIEW,
            Permissions::LIBRARY_BITS,
            everyone_overwrite,
            &role_overwrites,
            user_overwrite,
            server.is_admin(),
            false,
        );

        access.push(LibraryAccess {
            id: library.id,
            name: library.name,
            permissions,
        });
    }

    Ok(AuthzContext {
        user_id,
        server,
        roles: user_roles,
        role_ids,
        everyone_role_id: everyone.id,
        libraries: access,
    })
}

pub async fn playlist_overwrites(
    pool: &PgPool,
    context: &AuthzContext,
) -> Result<HashMap<Uuid, Vec<OverwriteRecord>>, ApiError> {
    let mut overwrite_role_ids = context.role_ids.clone();
    overwrite_role_ids.push(context.everyone_role_id);
    let records =
        permissions::list_for_user(pool, "playlist", context.user_id, &overwrite_role_ids).await?;
    let mut grouped = HashMap::<Uuid, Vec<OverwriteRecord>>::new();

    for record in records {
        grouped.entry(record.resource_id).or_default().push(record);
    }

    Ok(grouped)
}

#[must_use]
pub fn resolve_playlist(
    context: &AuthzContext,
    playlist: &PlaylistRecord,
    overwrites: &[OverwriteRecord],
) -> Permissions {
    let everyone_overwrite =
        overwrite_for(overwrites, playlist.id, "role", context.everyone_role_id);
    let role_overwrites = context
        .role_ids
        .iter()
        .filter_map(|role_id| overwrite_for(overwrites, playlist.id, "role", *role_id))
        .collect::<Vec<_>>();
    let user_overwrite = overwrite_for(overwrites, playlist.id, "user", context.user_id);

    let mut permissions = resolve_resource(
        context.server,
        Permissions::PLAYLIST_VIEW,
        Permissions::PLAYLIST_BITS,
        everyone_overwrite,
        &role_overwrites,
        user_overwrite,
        context.is_admin(),
        playlist.owner_id == context.user_id,
    );

    if context.server.contains(Permissions::PLAYLIST_VIEW_ALL) {
        permissions = permissions.union(Permissions::PLAYLIST_VIEW);
    }

    permissions
}

fn overwrite_for(
    records: &[OverwriteRecord],
    resource_id: Uuid,
    target_type: &str,
    target_id: Uuid,
) -> Option<Overwrite> {
    records
        .iter()
        .find(|record| {
            record.resource_id == resource_id
                && record.target_type == target_type
                && record.target_id == target_id
        })
        .map(|record| {
            Overwrite::new(
                permissions_from_i64(record.allow),
                permissions_from_i64(record.deny),
            )
        })
}

#[must_use]
pub fn permissions_from_i64(value: i64) -> Permissions {
    Permissions::from_bits(u64::try_from(value.max(0)).unwrap_or(0))
}
