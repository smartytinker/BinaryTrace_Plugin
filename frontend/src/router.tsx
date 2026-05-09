import { createBrowserRouter } from 'react-router-dom'
import { AppShell } from './ui/AppShell'
import { HomePage } from './views/HomePage'
import { ReportPage } from './views/ReportPage'
import { NotFoundPage } from './views/NotFoundPage'

export const router = createBrowserRouter([
  {
    path: '/',
    element: <AppShell />,
    children: [
      { index: true, element: <HomePage /> },
      { path: 'report/:fileHash', element: <ReportPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
])

