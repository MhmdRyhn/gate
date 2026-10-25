package httpapi

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/MhmdRyhn/gate/internal/domain"
	"github.com/MhmdRyhn/gate/internal/rbac"
	"github.com/MhmdRyhn/gate/internal/service"
)

// AdminHandler serves the internal (staff) API under /v1/admin.
type AdminHandler struct {
	users *service.UserService
	roles *service.RoleService
	audit *service.Auditor
	ew    errorWriter
}

// NewAdminHandler wires an AdminHandler.
func NewAdminHandler(u *service.UserService, r *service.RoleService, a *service.Auditor, log *zap.Logger) *AdminHandler {
	return &AdminHandler{users: u, roles: r, audit: a, ew: errorWriter{log: log}}
}

// --- registry ----------------------------------------------------------------

func (h *AdminHandler) listPermissions(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"items": rbac.Permissions})
}

func (h *AdminHandler) listPublicTypes(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"items": rbac.PublicUserTypes})
}

// --- users -------------------------------------------------------------------

func (h *AdminHandler) listUsers(c *gin.Context) {
	limit, offset, ok := h.page(c)
	if !ok {
		return
	}
	f := domain.UserFilter{Limit: limit, Offset: offset}
	if v := c.Query("kind"); v != "" {
		k := domain.UserKind(v)
		f.Kind = &k
	}
	if v := c.Query("public_type"); v != "" {
		f.PublicType = &v
	}
	users, err := h.users.List(c.Request.Context(), f)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	items := make([]userResponse, len(users))
	for i := range users {
		items[i] = newUserResponse(&users[i], nil)
	}
	c.JSON(http.StatusOK, listResponse[userResponse]{Items: items, Limit: limit, Offset: offset})
}

func (h *AdminHandler) createUser(c *gin.Context) {
	var req createUserRequest
	if err := bindJSON(c, &req); err != nil {
		h.ew.write(c, err)
		return
	}
	d, err := h.users.Create(c.Request.Context(), principalFrom(c), service.CreateUserInput{
		Email: req.Email, Phone: req.Phone, FullName: req.FullName, Password: req.Password,
		Kind: domain.UserKind(req.Kind), RoleIDs: req.RoleIDs, PublicTypes: req.PublicTypes,
	})
	if err != nil {
		h.ew.write(c, err)
		return
	}
	c.JSON(http.StatusCreated, newUserDetailsResponse(d))
}

func (h *AdminHandler) getUser(c *gin.Context) {
	id, ok := h.pathID(c)
	if !ok {
		return
	}
	d, err := h.users.Get(c.Request.Context(), id)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	c.JSON(http.StatusOK, newUserDetailsResponse(d))
}

func (h *AdminHandler) updateUser(c *gin.Context) {
	id, ok := h.pathID(c)
	if !ok {
		return
	}
	var req updateUserRequest
	if err := bindJSON(c, &req); err != nil {
		h.ew.write(c, err)
		return
	}
	patch := domain.UserPatch{FullName: req.FullName}
	if req.Status != nil {
		s := domain.UserStatus(*req.Status)
		patch.Status = &s
	}
	d, err := h.users.Update(c.Request.Context(), principalFrom(c), id, patch)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	c.JSON(http.StatusOK, newUserDetailsResponse(d))
}

func (h *AdminHandler) setUserRoles(c *gin.Context) {
	id, ok := h.pathID(c)
	if !ok {
		return
	}
	var req setRolesRequest
	if err := bindJSON(c, &req); err != nil {
		h.ew.write(c, err)
		return
	}
	d, err := h.users.SetRoles(c.Request.Context(), principalFrom(c), id, req.RoleIDs)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	c.JSON(http.StatusOK, newUserDetailsResponse(d))
}

func (h *AdminHandler) setUserPublicTypes(c *gin.Context) {
	id, ok := h.pathID(c)
	if !ok {
		return
	}
	var req setPublicTypesRequest
	if err := bindJSON(c, &req); err != nil {
		h.ew.write(c, err)
		return
	}
	d, err := h.users.SetPublicTypes(c.Request.Context(), principalFrom(c), id, req.PublicTypes)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	c.JSON(http.StatusOK, newUserDetailsResponse(d))
}

// --- roles -------------------------------------------------------------------

func (h *AdminHandler) listRoles(c *gin.Context) {
	roles, err := h.roles.List(c.Request.Context())
	if err != nil {
		h.ew.write(c, err)
		return
	}
	items := make([]roleResponse, len(roles))
	for i := range roles {
		items[i] = newRoleResponse(&roles[i])
	}
	c.JSON(http.StatusOK, listResponse[roleResponse]{Items: items})
}

func (h *AdminHandler) getRole(c *gin.Context) {
	id, ok := h.pathID(c)
	if !ok {
		return
	}
	r, err := h.roles.Get(c.Request.Context(), id)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	c.JSON(http.StatusOK, newRoleResponse(r))
}

func (h *AdminHandler) createRole(c *gin.Context) {
	in, ok := h.roleInput(c)
	if !ok {
		return
	}
	if in.Name == nil {
		writeProblem(c, http.StatusBadRequest, "invalid_request", "name is required")
		return
	}
	r, err := h.roles.Create(c.Request.Context(), principalFrom(c), in)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	c.JSON(http.StatusCreated, newRoleResponse(r))
}

func (h *AdminHandler) updateRole(c *gin.Context) {
	id, ok := h.pathID(c)
	if !ok {
		return
	}
	in, ok := h.roleInput(c)
	if !ok {
		return
	}
	r, err := h.roles.Update(c.Request.Context(), principalFrom(c), id, in)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	c.JSON(http.StatusOK, newRoleResponse(r))
}

func (h *AdminHandler) deleteRole(c *gin.Context) {
	id, ok := h.pathID(c)
	if !ok {
		return
	}
	if err := h.roles.Delete(c.Request.Context(), principalFrom(c), id); err != nil {
		h.ew.write(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// --- audit -------------------------------------------------------------------

func (h *AdminHandler) listAudit(c *gin.Context) {
	limit, offset, ok := h.page(c)
	if !ok {
		return
	}
	f := domain.AuditFilter{Limit: limit, Offset: offset, Action: c.Query("action")}
	if v := c.Query("actor_user_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeProblem(c, http.StatusBadRequest, "invalid_request", "actor_user_id must be a UUID")
			return
		}
		f.ActorUserID = &id
	}
	events, err := h.audit.List(c.Request.Context(), f)
	if err != nil {
		h.ew.write(c, err)
		return
	}
	items := make([]auditEventResponse, len(events))
	for i, e := range events {
		items[i] = auditEventResponse{ID: e.ID, OccurredAt: e.OccurredAt, ActorUserID: e.ActorUserID, Action: e.Action,
			TargetType: e.TargetType, TargetID: e.TargetID, IP: e.IP, UserAgent: e.UserAgent, RequestID: e.RequestID, Details: e.Details}
	}
	c.JSON(http.StatusOK, listResponse[auditEventResponse]{Items: items, Limit: limit, Offset: offset})
}

// --- helpers -----------------------------------------------------------------

func (h *AdminHandler) roleInput(c *gin.Context) (service.RoleInput, bool) {
	var req roleRequest
	if err := bindJSON(c, &req); err != nil {
		h.ew.write(c, err)
		return service.RoleInput{}, false
	}
	in := service.RoleInput{Name: req.Name, Description: req.Description}
	if req.Permissions != nil {
		perms := make([]domain.Permission, len(*req.Permissions))
		for i, p := range *req.Permissions {
			perms[i] = domain.Permission(p)
		}
		in.Permissions = &perms
	}
	return in, true
}

func (h *AdminHandler) pathID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeProblem(c, http.StatusBadRequest, "invalid_request", "id must be a UUID")
		return uuid.Nil, false
	}
	return id, true
}

// page parses limit (1-200, default 50) and offset (0-100000) query
// parameters. Deep offsets are capped; see docs/security.md on pagination.
func (h *AdminHandler) page(c *gin.Context) (int, int, bool) {
	limit, err1 := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, err2 := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if err1 != nil || err2 != nil || limit < 1 || limit > 200 || offset < 0 || offset > 100_000 {
		writeProblem(c, http.StatusBadRequest, "invalid_request", "limit must be 1-200 and offset 0-100000")
		return 0, 0, false
	}
	return limit, offset, true
}
