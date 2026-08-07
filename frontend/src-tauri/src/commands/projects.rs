use crate::database::{Database, Project};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProjectData {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProjectData {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
}

#[tauri::command]
pub async fn list_projects(status: Option<String>) -> Result<Vec<Project>> {
    info!("Listing projects with status: {:?}", status);

    let db = Database::new()?;
    db.list_projects(status.as_deref())
}

#[tauri::command]
pub async fn get_project(id: String) -> Result<Option<Project>> {
    info!("Getting project: {}", id);

    let db = Database::new()?;
    db.get_project(&id)
}

#[tauri::command]
pub async fn create_project(data: CreateProjectData) -> Result<Project> {
    info!("Creating project: {}", data.name);

    let db = Database::new()?;
    db.create_project(&data.name, data.description.as_deref())
}

#[tauri::command]
pub async fn update_project(id: String, data: UpdateProjectData) -> Result<Project> {
    info!("Updating project: {} with data: {:?}", id, data);

    let db = Database::new()?;
    db.update_project(
        &id,
        data.name.as_deref(),
        data.description.as_deref(),
        data.status.as_deref(),
    )?;

    db.get_project(&id)?
        .ok_or_else(|| crate::error::AppError::NotFound(format!("Project {} not found", id)))
}

#[tauri::command]
pub async fn delete_project(id: String) -> Result<()> {
    info!("Deleting project: {}", id);

    let db = Database::new()?;
    db.delete_project(&id)
}

#[tauri::command]
pub async fn assign_assessment_to_project(
    assessment_id: String,
    project_id: Option<String>,
) -> Result<()> {
    info!(
        "Assigning assessment {} to project {:?}",
        assessment_id, project_id
    );

    let db = Database::new()?;
    db.assign_assessment_to_project(&assessment_id, project_id.as_deref())
}
