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

        [HttpPost]
        [Authorize]
        public IActionResult CreateTask([FromBody] string title, [FromBody] string description)
        {
            var task = new Models.Task
            {
                Title = title,
                Description = description,
                OwnerLogin = User.Identity?.Name,
                IsCompleted = false
            };

            _context.Tasks.Add(task);
            _context.SaveChanges();

            return Created($"api/tasks/{task.Id}", new
            {
                created_task = task
            });
        }

        [HttpPut("{id:int}")]
        [Authorize]
        public IActionResult ChangeTask([FromRoute] int id, [FromBody] string title, [FromBody] string description, [FromBody] bool complete)
        {
            var task = _context.Tasks.Find(id);

            if (task == null)
                return NotFound();

            if (task.OwnerLogin != User.Identity?.Name && !User.IsInRole("Admin"))
                return Forbid();

            task.Title = title;
            task.Description = description;
            task.IsCompleted = complete;

            _context.SaveChanges();

            return Ok(new
            {
                changed_task = task
            });
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
