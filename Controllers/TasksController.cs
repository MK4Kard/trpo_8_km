using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using trpo_8.Models;

namespace trpo_8.Controllers
{
    [ApiController]
    [Route("api/v1/[controller]")]
    public class TasksController : ControllerBase
    {
        private readonly KardashinDbContext _context = new();

        [HttpGet]
        [Authorize]
        public IActionResult GetTasks()
        {
            var tasks = _context.Tasks.Where(t => t.OwnerLogin == User.Identity.Name).ToList();

            return Ok(tasks);
        }

        [HttpGet("{id:int}")]
        [Authorize]
        public IActionResult GetTaskId([FromRoute] int id)
        {
            var task = _context.Tasks.Find(id);

            if (task == null)
                return NotFound();

            if (task.OwnerLogin != User.Identity?.Name && !User.IsInRole("Admin"))
                return Forbid();

            return Ok(task);
        }

        public record TaskData(string Title, string Description, bool IsCompleted);

        [HttpPost]
        [Authorize]
        public IActionResult CreateTask([FromBody] TaskData taskData)
        {
            var task = new Models.Task
            {
                Title = taskData.Title,
                Description = taskData.Description,
                OwnerLogin = User.Identity?.Name,
                IsCompleted = false
            };

            _context.Tasks.Add(task);
            _context.SaveChanges();

            return Created($"api/tasks/{task.Id}", task);
        }

        [HttpPut("{id:int}")]
        [Authorize]
        public IActionResult ChangeTask([FromRoute] int id, [FromBody] TaskData taskData)
        {
            var task = _context.Tasks.Find(id);

            if (task == null)
                return NotFound();

            if (task.OwnerLogin != User.Identity?.Name && !User.IsInRole("Admin"))
                return Forbid();

            task.Title = taskData.Title;
            task.Description = taskData.Description;
            task.IsCompleted = taskData.IsCompleted;

            _context.SaveChanges();

            return Ok(task);
        }

        [HttpDelete("{id:int}")]
        [Authorize]
        public IActionResult RemoveTask([FromRoute] int id)
        {
            var task = _context.Tasks.Find(id);

            if (task == null)
                return NotFound();

            if (task.OwnerLogin != User.Identity?.Name && !User.IsInRole("Admin"))
                return Forbid();

            _context.Tasks.Remove(task);
            _context.SaveChanges();

            return NoContent();
        }

        [HttpGet("all")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetAllTasks()
        {
            var tasks = _context.Tasks.ToList();

            return Ok(tasks);
        }
    }
}
