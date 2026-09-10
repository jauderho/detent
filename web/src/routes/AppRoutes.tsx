/**
 * The route table.
 *
 * `/login` is the only address outside the guard. Everything else is nested
 * under one `RequireAuth` element rather than wrapped case by case, so a route
 * added later is behind the guard by construction instead of by remembering.
 */

import { Route, Routes } from 'react-router'
import { LoginPage } from './LoginPage'
import {
  AuditPage,
  BackupsPage,
  CertificatesPage,
  DashboardPage,
  ModuleDetailPage,
  ModulesPage,
  NotFoundPage,
  ServicesPage,
  SettingsPage,
} from './pages'
import { ROUTES } from './paths'
import { RequireAuth } from './RequireAuth'

export function AppRoutes() {
  return (
    <Routes>
      <Route path={ROUTES.login} element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route path={ROUTES.dashboard} element={<DashboardPage />} />
        <Route path={ROUTES.modules} element={<ModulesPage />} />
        <Route path={ROUTES.moduleDetail} element={<ModuleDetailPage />} />
        <Route path={ROUTES.services} element={<ServicesPage />} />
        <Route path={ROUTES.backups} element={<BackupsPage />} />
        <Route path={ROUTES.audit} element={<AuditPage />} />
        <Route path={ROUTES.certificates} element={<CertificatesPage />} />
        <Route path={ROUTES.settings} element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}
